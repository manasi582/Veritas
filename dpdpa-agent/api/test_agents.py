"""
Agent Management API — Tests (Block 2)
=======================================
Covers all six agent endpoints plus the auth guard on /v1/{org_id}/events.

Run with: python -m pytest api/test_agents.py -v
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import agent_store.store as agent_store_module
import evidence_store.store as store_module
import user_store.store as user_store_module
from agent_store.store import get_agent_store, reset_agent_store
from dashboard import live_feed
from dashboard.server import app
from rate_limit import _limiter
from user_store.store import get_user_store, reset_user_store
from user_store.models import UserRole

client = TestClient(app)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_admin():
    from passlib.context import CryptContext
    pw_hash = CryptContext(schemes=["bcrypt"], deprecated="auto").hash("testpass123!")
    get_user_store().create_user("testadmin", "admin@test.io", pw_hash, UserRole.SUPER_ADMIN)
    r = client.post("/api/auth/login", data={"username": "testadmin", "password": "testpass123!"})
    assert r.status_code == 200, f"Login failed in test setup: {r.text}"


@pytest.fixture(autouse=True)
def isolated_stores(tmp_path, monkeypatch):
    """Fresh, isolated stores for every test + auto-login as SUPER_ADMIN."""
    monkeypatch.setattr(store_module, "_DEFAULT_DB_PATH", tmp_path / "test_evidence.db")
    monkeypatch.setattr(agent_store_module, "_DEFAULT_DB_PATH", tmp_path / "test_agents.db")
    monkeypatch.setattr(user_store_module, "_DEFAULT_DB_PATH", tmp_path / "test_users.db")
    monkeypatch.setenv("VERITAS_SECURE_COOKIES", "false")
    monkeypatch.setenv("VERITAS_JWT_SECRET", "test-jwt-secret-for-unit-tests-only")
    store_module.reset_store()
    reset_agent_store()
    reset_user_store()
    live_feed._ws_clients.clear()
    _limiter._windows.clear()   # prevent rate-limit state leaking between tests

    _make_admin()

    yield
    store_module.reset_store()
    reset_agent_store()
    reset_user_store()
    live_feed._ws_clients.clear()
    _limiter._windows.clear()
    client.cookies.clear()


def _register_agent(org_id: str = "retail_co", source_label: str = "test-service") -> tuple[str, str]:
    """Helper: issue key → register agent. Returns (agent_id, auth_token)."""
    # Issue key via API
    key_resp = client.post("/agents/issue-key", json={"org_id": org_id})
    assert key_resp.status_code == 200
    key = key_resp.json()["key"]

    # Register via API
    reg_resp = client.post("/agent/register", json={
        "registration_key": key,
        "source_label": source_label,
    })
    assert reg_resp.status_code == 200
    data = reg_resp.json()
    return data["agent_id"], data["auth_token"]


# ---------------------------------------------------------------------------
# POST /agents/issue-key
# ---------------------------------------------------------------------------

class TestIssueKey:

    def test_valid_org_returns_key(self):
        r = client.post("/agents/issue-key", json={"org_id": "retail_co"})
        assert r.status_code == 200
        data = r.json()
        assert "key" in data
        assert data["org_id"] == "retail_co"
        assert data["expires_in_seconds"] == 1800

    def test_unknown_org_returns_404(self):
        r = client.post("/agents/issue-key", json={"org_id": "nonexistent_org_xyz"})
        assert r.status_code == 404
        assert "nonexistent_org_xyz" in r.json()["detail"]

    def test_keys_are_different_on_each_call(self):
        r1 = client.post("/agents/issue-key", json={"org_id": "retail_co"})
        r2 = client.post("/agents/issue-key", json={"org_id": "retail_co"})
        assert r1.json()["key"] != r2.json()["key"]

    def test_missing_org_id_returns_422(self):
        r = client.post("/agents/issue-key", json={})
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# POST /agent/register
# ---------------------------------------------------------------------------

class TestRegisterAgent:

    def test_valid_key_returns_identity(self):
        key_resp = client.post("/agents/issue-key", json={"org_id": "retail_co"})
        key = key_resp.json()["key"]

        r = client.post("/agent/register", json={"registration_key": key, "source_label": "order-service"})
        assert r.status_code == 200
        data = r.json()
        assert data["agent_id"].startswith("VERITAS-AGENT-")
        assert len(data["auth_token"]) > 0
        assert data["org_id"] == "retail_co"
        assert data["event_endpoint"] == "/v1/retail_co/events"

    def test_used_key_rejected(self):
        key_resp = client.post("/agents/issue-key", json={"org_id": "retail_co"})
        key = key_resp.json()["key"]

        client.post("/agent/register", json={"registration_key": key})
        r = client.post("/agent/register", json={"registration_key": key})
        assert r.status_code == 400
        assert "already been used" in r.json()["detail"]

    def test_fake_key_rejected(self):
        r = client.post("/agent/register", json={"registration_key": "totally-fake-key-xyz"})
        assert r.status_code == 400
        assert "invalid" in r.json()["detail"].lower()

    def test_expired_key_rejected(self, monkeypatch):
        from datetime import timedelta, timezone
        import agent_store.store as store_mod

        key_resp = client.post("/agents/issue-key", json={"org_id": "retail_co"})
        key = key_resp.json()["key"]

        # Advance clock past expiry
        future = __import__("datetime").datetime.now(timezone.utc) + timedelta(hours=2)
        monkeypatch.setattr(store_mod, "_now", lambda: future)

        r = client.post("/agent/register", json={"registration_key": key})
        assert r.status_code == 400
        assert "expired" in r.json()["detail"].lower()

    def test_source_label_optional(self):
        key_resp = client.post("/agents/issue-key", json={"org_id": "retail_co"})
        key = key_resp.json()["key"]
        r = client.post("/agent/register", json={"registration_key": key})
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# POST /agent/heartbeat
# ---------------------------------------------------------------------------

class TestHeartbeat:

    def test_valid_token_updates_heartbeat(self):
        agent_id, token = _register_agent()
        r = client.post(
            "/agent/heartbeat",
            json={"agent_id": agent_id},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_invalid_token_returns_401(self):
        agent_id, _ = _register_agent()
        r = client.post(
            "/agent/heartbeat",
            json={"agent_id": agent_id},
            headers={"Authorization": "Bearer invalid-token-xyz"},
        )
        assert r.status_code == 401

    def test_no_token_returns_401(self):
        agent_id, _ = _register_agent()
        r = client.post("/agent/heartbeat", json={"agent_id": agent_id})
        assert r.status_code == 401

    def test_mismatched_agent_id_returns_403(self):
        agent_id, token = _register_agent()
        agent_id2, _ = _register_agent(source_label="other-service")
        r = client.post(
            "/agent/heartbeat",
            json={"agent_id": agent_id2},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# GET /agents
# ---------------------------------------------------------------------------

class TestListAgents:

    def test_returns_empty_list_initially(self):
        r = client.get("/agents")
        assert r.status_code == 200
        assert r.json()["agents"] == []

    def test_returns_registered_agents(self):
        _register_agent(source_label="svc-a")
        _register_agent(source_label="svc-b")
        r = client.get("/agents")
        assert r.status_code == 200
        assert len(r.json()["agents"]) == 2

    def test_org_id_filter_works(self):
        _register_agent("retail_co", "svc-a")
        _register_agent("edtech_co", "svc-b")

        r_retail_co = client.get("/agents?org_id=retail_co")
        r_edtech = client.get("/agents?org_id=edtech_co")

        retail_co_agents = r_retail_co.json()["agents"]
        edtech_agents = r_edtech.json()["agents"]

        assert len(retail_co_agents) == 1
        assert retail_co_agents[0]["org_id"] == "retail_co"
        assert len(edtech_agents) == 1
        assert edtech_agents[0]["org_id"] == "edtech_co"


# ---------------------------------------------------------------------------
# GET /agents/{agent_id}
# ---------------------------------------------------------------------------

class TestGetAgent:

    def test_found_returns_detail(self):
        agent_id, _ = _register_agent(source_label="order-service")
        r = client.get(f"/agents/{agent_id}")
        assert r.status_code == 200
        data = r.json()
        assert data["agent_id"] == agent_id
        assert data["org_id"] == "retail_co"
        assert data["source_label"] == "order-service"
        assert data["status"] == "ACTIVE"

    def test_not_found_returns_404(self):
        r = client.get("/agents/VERITAS-AGENT-FAKE00")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# POST /agents/{agent_id}/revoke
# ---------------------------------------------------------------------------

class TestRevokeAgent:

    def test_revoke_sets_status_to_revoked(self):
        agent_id, _ = _register_agent()
        r = client.post(f"/agents/{agent_id}/revoke")
        assert r.status_code == 200
        assert r.json()["status"] == "REVOKED"

        detail = client.get(f"/agents/{agent_id}")
        assert detail.json()["status"] == "REVOKED"

    def test_revoke_unknown_agent_returns_404(self):
        r = client.post("/agents/VERITAS-AGENT-FAKE00/revoke")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Auth guard on POST /v1/{org_id}/events
# ---------------------------------------------------------------------------

class TestEventsEndpointAuth:

    def test_no_auth_header_returns_401(self):
        r = client.post(
            "/v1/retail_co/events",
            json={"source_type": "log", "source_system": "x", "raw_snippet": "hello"},
        )
        assert r.status_code == 401

    def test_invalid_token_returns_401(self):
        r = client.post(
            "/v1/retail_co/events",
            headers={"Authorization": "Bearer not-a-real-token"},
            json={"source_type": "log", "source_system": "x", "raw_snippet": "hello"},
        )
        assert r.status_code == 401

    def test_revoked_agent_returns_403(self):
        agent_id, token = _register_agent()
        client.post(f"/agents/{agent_id}/revoke")

        r = client.post(
            "/v1/retail_co/events",
            headers={"Authorization": f"Bearer {token}"},
            json={"source_type": "log", "source_system": "x", "raw_snippet": "hello"},
        )
        assert r.status_code == 403
        assert "revoked" in r.json()["detail"].lower()

    def test_token_from_wrong_org_returns_403(self):
        # Register agent for edtech_co, try to submit to retail_co
        _, edtech_token = _register_agent("edtech_co", "edtech-svc")

        r = client.post(
            "/v1/retail_co/events",
            headers={"Authorization": f"Bearer {edtech_token}"},
            json={"source_type": "log", "source_system": "x", "raw_snippet": "hello"},
        )
        assert r.status_code == 403
        assert "not authorized" in r.json()["detail"].lower() or "edtech_co" in r.json()["detail"]

    def test_valid_token_and_correct_org_accepted(self):
        _, token = _register_agent("retail_co")

        r = client.post(
            "/v1/retail_co/events",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "source_type": "log",
                "source_system": "order-service",
                "raw_snippet": "clean log line with no PII",
            },
        )
        assert r.status_code == 200

    def test_valid_token_increments_event_counter(self):
        agent_id, token = _register_agent("retail_co")

        for _ in range(3):
            client.post(
                "/v1/retail_co/events",
                headers={"Authorization": f"Bearer {token}"},
                json={"source_type": "log", "source_system": "x", "raw_snippet": "clean line"},
            )

        detail = client.get(f"/agents/{agent_id}").json()
        assert detail["events_received"] == 3

    def test_malformed_bearer_header_returns_401(self):
        r = client.post(
            "/v1/retail_co/events",
            headers={"Authorization": "Token abc123"},  # wrong scheme
            json={"source_type": "log", "source_system": "x", "raw_snippet": "hello"},
        )
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# Heartbeat health report (agent v1.0.18+)
# ---------------------------------------------------------------------------

HEALTH = {
    "agent_version": "1.0.18",
    "uptime_seconds": 3600,
    "queue_depth": 12,
    "queue_capacity": 1000,
    "counters": {"lines_read": 500, "forwarded": 480, "retries": 3,
                 "dropped_buffer_full": 0, "dropped_rejected": 2, "dropped_auth": 0, "dropped_other": 0},
    "sources": [
        {"type": "file", "target": "/var/log/app/orders.log", "source_system": "order-service",
         "state": "reading", "detail": "", "last_line_at": "2026-10-06T10:00:00+00:00"},
        {"type": "file", "target": "/var/log/app/secret.log", "source_system": "kyc-service",
         "state": "error", "detail": "Permission denied", "last_line_at": None},
    ],
}


class TestHeartbeatHealth:

    def _beat(self, agent_id, token, body):
        return client.post("/agent/heartbeat", json=body,
                           headers={"Authorization": f"Bearer {token}"})

    def test_health_report_is_stored_and_listed(self):
        agent_id, token = _register_agent()
        r = self._beat(agent_id, token, {"agent_id": agent_id, "health": HEALTH})
        assert r.status_code == 200
        agents = client.get("/agents?org_id=retail_co").json()["agents"]
        a = next(x for x in agents if x["agent_id"] == agent_id)
        assert a["agent_version"] == "1.0.18"
        assert a["health"]["queue_depth"] == 12
        assert a["health"]["counters"]["dropped_rejected"] == 2
        assert [s["state"] for s in a["health"]["sources"]] == ["reading", "error"]
        assert a["health_updated_at"] is not None

    def test_old_agents_without_health_still_work(self):
        agent_id, token = _register_agent()
        r = self._beat(agent_id, token, {"agent_id": agent_id})
        assert r.status_code == 200
        a = client.get(f"/agents/{agent_id}").json()
        assert a["health"] is None and a["agent_version"] is None
        assert a["last_heartbeat_at"] is not None

    def test_a_later_heartbeat_without_health_keeps_the_last_report(self):
        agent_id, token = _register_agent()
        self._beat(agent_id, token, {"agent_id": agent_id, "health": HEALTH})
        self._beat(agent_id, token, {"agent_id": agent_id})
        assert client.get(f"/agents/{agent_id}").json()["agent_version"] == "1.0.18"

    def test_health_is_replaced_by_the_newest_report(self):
        agent_id, token = _register_agent()
        self._beat(agent_id, token, {"agent_id": agent_id, "health": HEALTH})
        newer = {**HEALTH, "agent_version": "1.0.19", "queue_depth": 0}
        self._beat(agent_id, token, {"agent_id": agent_id, "health": newer})
        a = client.get(f"/agents/{agent_id}").json()
        assert a["agent_version"] == "1.0.19" and a["health"]["queue_depth"] == 0

    @pytest.mark.parametrize("bad", [
        {"sources": [{"type": "file", "state": "reading"}] * 51},                       # too many sources
        {"sources": [{"type": "file", "state": "exploding"}]},                           # unknown state
        {"counters": {f"c{i}": 1 for i in range(21)}},                                    # too many counters
        {"counters": {"x" * 41: 1}},                                                      # counter name too long
        {"agent_version": "v" * 65},                                                      # version too long
        {"queue_depth": -1},                                                              # negative number
        {"sources": [{"type": "file", "detail": "d" * 201, "state": "error"}]},           # detail too long
    ])
    def test_oversized_or_invalid_reports_are_rejected(self, bad):
        agent_id, token = _register_agent()
        r = self._beat(agent_id, token, {"agent_id": agent_id, "health": {**HEALTH, **bad}})
        assert r.status_code == 422

    def test_revoked_agent_cannot_report(self):
        agent_id, token = _register_agent()
        client.post(f"/agents/{agent_id}/revoke")
        r = self._beat(agent_id, token, {"agent_id": agent_id, "health": HEALTH})
        assert r.status_code == 403
        assert client.get(f"/agents/{agent_id}").json()["health"] is None


def test_agent_store_migrates_a_database_created_before_health_columns(tmp_path):
    import sqlite3
    from agent_store.store import AgentStore

    db = tmp_path / "old_agents.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE agents (
            agent_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'ACTIVE', source_label TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL, last_heartbeat_at TEXT, events_received INTEGER NOT NULL DEFAULT 0);
        INSERT INTO agents (agent_id, org_id, token_hash, created_at, events_received)
        VALUES ('VERITAS-AGENT-OLD', 'retail_co', 'h', '2026-01-01T00:00:00+00:00', 7);
    """)
    conn.commit()
    conn.close()

    store = AgentStore(db)
    agent = store.get_agent("VERITAS-AGENT-OLD")
    assert agent.events_received == 7 and agent.health is None and agent.agent_version is None
    store.record_heartbeat("VERITAS-AGENT-OLD", health={"agent_version": "1.0.18", "queue_depth": 3})
    again = store.get_agent("VERITAS-AGENT-OLD")
    assert again.agent_version == "1.0.18" and again.health["queue_depth"] == 3
    store.close()


def test_health_report_built_by_the_real_agent_is_accepted_by_the_server(monkeypatch):
    """Contract test: whatever veritas-agent/agent.py sends, the server's model must accept."""
    import importlib.util
    import queue
    from pathlib import Path

    agent_py = Path(__file__).resolve().parents[2] / "veritas-agent" / "agent.py"
    spec = importlib.util.spec_from_file_location("veritas_agent_for_contract_test", agent_py)
    agent_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent_mod)

    monkeypatch.setenv("VERITAS_AGENT_VERSION", "1.0.18")
    agent_mod.SOURCES.update("file", "/var/log/app/orders.log", source_system="order-service",
                             state="reading", last_line_at=agent_mod._now_iso())
    agent_mod.SOURCES.update("docker", "web", source_system="web", state="error", detail="log stream ended")
    q: queue.Queue = queue.Queue(maxsize=agent_mod.BUFFER_MAX)
    q.put(("x", "y"))
    health = agent_mod.build_health(q)

    agent_id, token = _register_agent()
    r = client.post("/agent/heartbeat", json={"agent_id": agent_id, "health": health},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    stored = client.get(f"/agents/{agent_id}").json()
    assert stored["agent_version"] == "1.0.18"
    assert stored["health"]["queue_depth"] == 1
    assert {s["state"] for s in stored["health"]["sources"]} == {"reading", "error"}


# ---------------------------------------------------------------------------
# Tenant isolation of agent management (found while adding health reporting:
# a user with no organisation could list every organisation's agents)
# ---------------------------------------------------------------------------

def _user_client(role: UserRole, orgs: tuple = (), name: str = "scoped") -> TestClient:
    """A separate logged-in client for a user with the given role and org grants."""
    from passlib.context import CryptContext
    pw_hash = CryptContext(schemes=["bcrypt"], deprecated="auto").hash("testpass123!")
    user = get_user_store().create_user(name, f"{name}@test.io", pw_hash, role)
    for org in orgs:
        get_user_store().grant_org_access(user.user_id, org)
    c = TestClient(app)
    r = c.post("/api/auth/login", data={"username": name, "password": "testpass123!"})
    assert r.status_code == 200, r.text
    return c


class TestAgentManagementIsTenantScoped:

    def _two_orgs_with_agents(self):
        a_id, _ = _register_agent(org_id="retail_co", source_label="agent-a")
        b_id, _ = _register_agent(org_id="edtech_co", source_label="agent-b")
        return a_id, b_id

    def test_user_with_no_orgs_sees_no_agents(self):
        self._two_orgs_with_agents()
        v = _user_client(UserRole.VIEWER, orgs=(), name="nobody")
        assert v.get("/agents").json()["agents"] == []

    def test_user_sees_only_their_own_orgs_agents(self):
        a_id, b_id = self._two_orgs_with_agents()
        v = _user_client(UserRole.VIEWER, orgs=("retail_co",), name="viewer_a")
        ids = [a["agent_id"] for a in v.get("/agents").json()["agents"]]
        assert ids == [a_id]

    def test_explicit_filter_for_another_org_is_forbidden(self):
        self._two_orgs_with_agents()
        v = _user_client(UserRole.VIEWER, orgs=("retail_co",), name="viewer_a")
        assert v.get("/agents?org_id=edtech_co").status_code == 403
        assert v.get("/agents?org_id=retail_co").status_code == 200

    def test_agent_detail_of_another_org_looks_like_not_found(self):
        a_id, b_id = self._two_orgs_with_agents()
        v = _user_client(UserRole.VIEWER, orgs=("retail_co",), name="viewer_a")
        assert v.get(f"/agents/{a_id}").status_code == 200
        assert v.get(f"/agents/{b_id}").status_code == 404

    def test_org_admin_cannot_issue_keys_for_another_org(self):
        self._two_orgs_with_agents()
        ca = _user_client(UserRole.COMPLIANCE_ADMIN, orgs=("retail_co",), name="admin_a")
        assert ca.post("/agents/issue-key", json={"org_id": "retail_co"}).status_code == 200
        assert ca.post("/agents/issue-key", json={"org_id": "edtech_co"}).status_code == 403

    def test_org_admin_cannot_revoke_another_orgs_agent(self):
        a_id, b_id = self._two_orgs_with_agents()
        ca = _user_client(UserRole.COMPLIANCE_ADMIN, orgs=("retail_co",), name="admin_a")
        assert ca.post(f"/agents/{b_id}/revoke").status_code == 404
        assert client.get(f"/agents/{b_id}").json()["status"] == "ACTIVE"
        assert ca.post(f"/agents/{a_id}/revoke").status_code == 200

    def test_super_admin_still_sees_everything(self):
        a_id, b_id = self._two_orgs_with_agents()
        ids = {a["agent_id"] for a in client.get("/agents").json()["agents"]}
        assert {a_id, b_id} <= ids

    def test_health_reports_are_not_visible_across_orgs(self):
        a_id, b_id = self._two_orgs_with_agents()
        _, token = _register_agent(org_id="edtech_co", source_label="agent-b2")
        b2 = [a for a in client.get("/agents?org_id=edtech_co").json()["agents"] if a["source_label"] == "agent-b2"][0]["agent_id"]
        client.post("/agent/heartbeat", json={"agent_id": b2, "health": HEALTH},
                    headers={"Authorization": f"Bearer {token}"})
        v = _user_client(UserRole.VIEWER, orgs=("retail_co",), name="viewer_a")
        assert v.get(f"/agents/{b2}").status_code == 404
        assert "/var/log/app/orders.log" not in v.get("/agents").text


# ---------------------------------------------------------------------------
# Reusable enrollment keys (Kubernetes DaemonSet: one key, many agents)
# ---------------------------------------------------------------------------

def _issue(org="retail_co", **body):
    r = client.post("/agents/issue-key", json={"org_id": org, **body})
    return r


def _register_with(key, label="node"):
    return client.post("/agent/register", json={"registration_key": key, "source_label": label})


class TestReusableKeys:

    def test_default_key_is_still_single_use_for_30_minutes(self):
        r = _issue()
        assert r.status_code == 200
        body = r.json()
        assert body["max_uses"] == 1 and body["expires_in_seconds"] == 1800
        assert _register_with(body["key"]).status_code == 200
        again = _register_with(body["key"])
        assert again.status_code == 400 and "already been used" in again.json()["detail"]

    def test_reusable_key_enrols_up_to_its_limit_then_stops(self):
        body = _issue(max_uses=3, label="prod cluster").json()
        assert body["expires_in_seconds"] == 86400, "reusable keys default to 24 hours"
        for i in range(3):
            assert _register_with(body["key"], f"node-{i}").status_code == 200
        over = _register_with(body["key"], "node-3")
        assert over.status_code == 400
        assert "use limit (3 agents)" in over.json()["detail"]

    def test_each_registration_creates_a_separate_agent_with_its_own_token(self):
        key = _issue(max_uses=2).json()["key"]
        a, b = _register_with(key, "n1").json(), _register_with(key, "n2").json()
        assert a["agent_id"] != b["agent_id"] and a["auth_token"] != b["auth_token"]
        ev = {"source_type": "log", "source_system": "order-service", "raw_snippet": "phone 9876543210"}
        for agent in (a, b):
            r = client.post(f"/v1/retail_co/events", json=ev,
                            headers={"Authorization": f"Bearer {agent['auth_token']}"})
            assert r.status_code == 200

    def test_listing_shows_uses_and_status_but_never_the_key(self):
        body = _issue(max_uses=2, label="staging").json()
        _register_with(body["key"])
        keys = client.get("/agents/keys?org_id=retail_co").json()["keys"]
        k = next(x for x in keys if x["key_id"] == body["key_id"])
        assert (k["label"], k["max_uses"], k["uses"], k["status"]) == ("staging", 2, 1, "ACTIVE")
        assert body["key"] not in client.get("/agents/keys?org_id=retail_co").text
        _register_with(body["key"])
        k = next(x for x in client.get("/agents/keys?org_id=retail_co").json()["keys"] if x["key_id"] == body["key_id"])
        assert k["status"] == "EXHAUSTED"

    def test_revoking_a_key_blocks_new_agents_but_not_existing_ones(self):
        body = _issue(max_uses=5).json()
        first = _register_with(body["key"]).json()
        assert client.post(f"/agents/keys/{body['key_id']}/revoke").status_code == 200
        blocked = _register_with(body["key"])
        assert blocked.status_code == 400 and "revoked" in blocked.json()["detail"]
        r = client.post("/agent/heartbeat", json={"agent_id": first["agent_id"]},
                        headers={"Authorization": f"Bearer {first['auth_token']}"})
        assert r.status_code == 200, "agents enrolled before the revocation keep working"
        status = next(x for x in client.get("/agents/keys?org_id=retail_co").json()["keys"]
                      if x["key_id"] == body["key_id"])["status"]
        assert status == "REVOKED"

    @pytest.mark.parametrize("bad", [
        {"max_uses": 0}, {"max_uses": 10001}, {"expires_in_seconds": 59},
        {"expires_in_seconds": 30 * 86400 + 1}, {"label": "x" * 101},
    ])
    def test_out_of_range_options_are_rejected(self, bad):
        assert _issue(**bad).status_code == 422

    def test_expiry_can_be_chosen(self):
        body = _issue(max_uses=2, expires_in_seconds=7 * 86400).json()
        assert body["expires_in_seconds"] == 7 * 86400

    def test_a_key_past_its_expiry_is_refused(self):
        from agent_store.store import get_agent_store as store
        plaintext, _ = store().issue_key_detailed("retail_co", max_uses=3, ttl_minutes=-5)
        r = _register_with(plaintext)
        assert r.status_code == 400 and "expired" in r.json()["detail"]

    def test_enrolling_a_big_cluster_from_one_ip_is_not_rate_limited(self):
        key = _issue(max_uses=30).json()["key"]
        statuses = [_register_with(key, f"node-{i}").status_code for i in range(30)]
        assert statuses == [200] * 30, "successful enrolments must not count toward the limit"

    def test_guessing_keys_is_still_rate_limited(self):
        codes = [_register_with(f"wrong-key-{i}").status_code for i in range(22)]
        assert codes[:20] == [400] * 20
        assert 429 in codes[20:], "after 20 failed attempts from one IP the endpoint must refuse"

    def test_key_actions_are_audited(self):
        body = _issue(max_uses=2, label="audit me").json()
        _register_with(body["key"], "node-a")
        client.post(f"/agents/keys/{body['key_id']}/revoke")
        from audit_log.store import get_audit_store
        actions = [e["action"] for e in get_audit_store().query(org_id="retail_co", limit=100)]
        assert {"AGENT_KEY_ISSUED", "AGENT_REGISTERED", "AGENT_KEY_REVOKED"} <= set(actions)

    def test_last_use_is_won_by_exactly_one_of_many_racing_agents(self):
        import threading
        from agent_store.store import get_agent_store as store
        plaintext, _ = store().issue_key_detailed("retail_co", max_uses=1)
        results = []
        def go():
            try:
                store().consume_key(plaintext)
                results.append("ok")
            except ValueError:
                results.append("refused")
        threads = [threading.Thread(target=go) for _ in range(12)]
        [t.start() for t in threads]; [t.join() for t in threads]
        assert results.count("ok") == 1 and results.count("refused") == 11


class TestKeyManagementIsTenantScoped:

    def test_org_admin_cannot_list_or_revoke_another_orgs_keys(self):
        other = _issue("edtech_co", max_uses=2).json()
        ca = _user_client(UserRole.COMPLIANCE_ADMIN, orgs=("retail_co",), name="keys_admin_a")
        assert ca.get("/agents/keys?org_id=edtech_co").status_code == 403
        assert ca.post(f"/agents/keys/{other['key_id']}/revoke").status_code == 404
        # and the key still works
        assert _register_with(other["key"]).status_code == 200

    def test_viewers_and_auditors_cannot_manage_keys(self):
        v = _user_client(UserRole.VIEWER, orgs=("retail_co",), name="keys_viewer")
        a = _user_client(UserRole.AUDITOR, orgs=("retail_co",), name="keys_auditor")
        for c in (v, a):
            assert c.get("/agents/keys?org_id=retail_co").status_code == 403
            assert c.post("/agents/issue-key", json={"org_id": "retail_co", "max_uses": 5}).status_code == 403


def test_agent_store_migrates_keys_created_before_reusable_keys(tmp_path):
    import sqlite3
    from agent_store.store import AgentStore
    import hashlib

    db = tmp_path / "old_keys.db"
    h = lambda v: hashlib.sha256(v.encode()).hexdigest()
    conn = sqlite3.connect(db)
    conn.executescript(f"""
        CREATE TABLE registration_keys (
            key_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0, used_at TEXT);
        CREATE TABLE agents (
            agent_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'ACTIVE', source_label TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL, last_heartbeat_at TEXT, events_received INTEGER NOT NULL DEFAULT 0);
        INSERT INTO registration_keys VALUES ('k-used','retail_co','{h("usedkey")}','2026-01-01T00:00:00+00:00','2099-01-01T00:00:00+00:00',1,'2026-01-01T00:01:00+00:00');
        INSERT INTO registration_keys VALUES ('k-open','retail_co','{h("openkey")}','2026-01-01T00:00:00+00:00','2099-01-01T00:00:00+00:00',0,NULL);
    """)
    conn.commit(); conn.close()

    store = AgentStore(db)
    used = store.get_key("k-used")
    assert (used.max_uses, used.uses, used.used) == (1, 1, True)
    with pytest.raises(ValueError, match="already been used"):
        store.consume_key("usedkey")
    assert store.consume_key("openkey").uses == 1
    with pytest.raises(ValueError, match="already been used"):
        store.consume_key("openkey")
    store.close()


# ---------------------------------------------------------------------------
# Version reporting and compatibility
# ---------------------------------------------------------------------------

class TestVersions:
    def test_registration_tells_the_agent_the_server_and_minimum_versions(self, monkeypatch):
        import veritas_version
        monkeypatch.setenv("VERITAS_VERSION", "7.7.7")
        veritas_version.get_version.cache_clear()
        try:
            key = client.post("/agents/issue-key", json={"org_id": "retail_co"}).json()["key"]
            data = client.post("/agent/register", json={"registration_key": key, "source_label": "v"}).json()
            assert data["server_version"] == "7.7.7"
            assert data["min_agent_version"] == veritas_version.MIN_AGENT_VERSION
        finally:
            veritas_version.get_version.cache_clear()

    def test_heartbeat_says_whether_the_agent_is_outdated(self):
        agent_id, token = _register_agent()
        hdr = {"Authorization": f"Bearer {token}"}
        old = client.post("/agent/heartbeat", headers=hdr,
                          json={"agent_id": agent_id, "health": {"agent_version": "1.0.10"}}).json()
        assert old["agent_outdated"] is True and old["min_agent_version"]
        no_health = client.post("/agent/heartbeat", headers=hdr, json={"agent_id": agent_id}).json()
        assert no_health["agent_outdated"] is True          # pre-1.0.18 agents send no health report
        current = client.post("/agent/heartbeat", headers=hdr,
                              json={"agent_id": agent_id, "health": {"agent_version": "99.0.0"}}).json()
        assert current["agent_outdated"] is False

    def test_agent_list_flags_outdated_agents(self):
        agent_id, token = _register_agent()
        client.post("/agent/heartbeat", headers={"Authorization": f"Bearer {token}"},
                    json={"agent_id": agent_id, "health": {"agent_version": "1.0.1"}})
        row = [a for a in client.get("/agents").json()["agents"] if a["agent_id"] == agent_id][0]
        assert row["agent_version"] == "1.0.1" and row["outdated"] is True
        client.post("/agent/heartbeat", headers={"Authorization": f"Bearer {token}"},
                    json={"agent_id": agent_id, "health": {"agent_version": "1.0.19"}})
        row = [a for a in client.get("/agents").json()["agents"] if a["agent_id"] == agent_id][0]
        assert row["outdated"] is False

    def test_system_health_reports_the_release_version(self, monkeypatch):
        import veritas_version
        monkeypatch.setenv("VERITAS_VERSION", "7.7.7")
        veritas_version.get_version.cache_clear()
        try:
            runtime = client.get("/api/system/health").json()["checks"]["runtime"]
            assert runtime["version"] == "7.7.7" and runtime["min_agent_version"]
        finally:
            veritas_version.get_version.cache_clear()


def test_heartbeat_carries_the_redaction_floor_of_approved_rules():
    from evidence_store.store import get_store
    from rulebook import changes
    store = get_store()
    org = "retail_co"
    c = changes.propose(store, org, changes.OVERLAY, {"actions": ["alert", "redact"], "redact_kinds": {"phone": "mask"}}, "alice", None, target="EXPOSURE_001")
    changes.approve(store, org, c["change_id"], "alice", self_approval_allowed=True)
    changes.invalidate(org)
    from rulebook import actions
    assert actions.redaction_for(store, org) == {"phone": "mask"}
