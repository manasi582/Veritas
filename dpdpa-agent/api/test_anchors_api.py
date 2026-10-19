"""The anchoring and export endpoints: who may call them, and what they return."""
import json

import pytest
from fastapi.testclient import TestClient

import agent_store.store as agent_store_module
import evidence_store.store as store_module
import user_store.store as user_store_module
from agent_store.store import reset_agent_store
from anchoring.checkpoints import reset_manager
from dashboard import live_feed
from dashboard.server import app
from evidence_store.store import get_store, reset_store
from evidence_store.test_evidence_store import _make_explained_verdict
from rate_limit import _limiter
from user_store.models import UserRole
from user_store.store import get_user_store, reset_user_store

ORG = "anchor_api_org"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "_DEFAULT_DB_PATH", tmp_path / "e.db")
    monkeypatch.setattr(agent_store_module, "_DEFAULT_DB_PATH", tmp_path / "a.db")
    monkeypatch.setattr(user_store_module, "_DEFAULT_DB_PATH", tmp_path / "u.db")
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VERITAS_SECURE_COOKIES", "false")
    monkeypatch.setenv("VERITAS_JWT_SECRET", "anchors-test-secret-key-anchors-test-secret")
    monkeypatch.delenv("VERITAS_ANCHOR_DIR", raising=False)
    monkeypatch.setenv("VERITAS_ANCHOR_CONFIG", str(tmp_path / "none.yaml"))
    reset_store(); reset_agent_store(); reset_user_store(); reset_manager()
    live_feed._ws_clients.clear(); _limiter._windows.clear()
    yield
    reset_manager(); reset_store(); reset_agent_store(); reset_user_store()
    _limiter._windows.clear()


def client(role, name):
    from passlib.context import CryptContext
    pw = CryptContext(schemes=["bcrypt"], deprecated="auto").hash("Passw0rd!x")
    u = get_user_store().create_user(name, f"{name}@t.io", pw, role)
    get_user_store().grant_org_access(u.user_id, ORG)
    c = TestClient(app, raise_server_exceptions=False)
    assert c.post("/api/auth/login", data={"username": name, "password": "Passw0rd!x"}).status_code == 200
    return c


def seed(n=3):
    for _ in range(n):
        get_store().append(_make_explained_verdict(tenant_id=ORG))


def test_evidence_export_is_a_header_and_one_line_per_record(monkeypatch):
    seed(3)
    c = client(UserRole.AUDITOR, "aud")
    r = c.get(f"/v1/{ORG}/evidence/export")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-ndjson")
    lines = [json.loads(x) for x in r.text.strip().splitlines()]
    head, recs = lines[0], lines[1:]
    assert head["format"] == "veritas-evidence-export" and head["org"] == ORG and head["record_count"] == 3
    assert [x["seq"] for x in recs] == [1, 2, 3] and recs[0]["hash_version"] == 1 and "body" in recs[0]


def test_an_export_is_audit_logged_with_who_asked():
    seed(1)
    client(UserRole.AUDITOR, "aud").get(f"/v1/{ORG}/evidence/export")
    from audit_log.store import get_audit_store
    entries = get_audit_store().query(limit=50) if hasattr(get_audit_store(), "query") else []
    assert any("EVIDENCE_EXPORTED" in json.dumps(e, default=str) and "aud" in json.dumps(e, default=str) for e in entries)


def test_a_viewer_cannot_export_or_see_anchors():
    seed(1)
    v = client(UserRole.VIEWER, "view")
    for path in ("evidence/export", "anchors", "anchors/export", "anchors/pubkey"):
        assert v.get(f"/v1/{ORG}/{path}").status_code == 403, path


def test_anchoring_off_says_so_and_run_is_refused_clearly():
    admin = client(UserRole.COMPLIANCE_ADMIN, "adm")
    body = admin.get(f"/v1/{ORG}/anchors").json()
    assert body["enabled"] is False and body["checkpoints"] == []
    r = admin.post(f"/v1/{ORG}/anchors/run")
    assert r.status_code == 409 and "not turned on" in r.json()["detail"]


def test_with_anchoring_on_a_run_makes_a_witnessed_checkpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_ANCHOR_DIR", str(tmp_path / "share"))
    reset_manager()
    seed(4)
    admin = client(UserRole.COMPLIANCE_ADMIN, "adm")
    r = admin.post(f"/v1/{ORG}/anchors/run").json()
    assert r["created"] is True and r["checkpoint"]["last_seq"] == 4
    listed = admin.get(f"/v1/{ORG}/anchors").json()
    assert listed["enabled"] and listed["checkpoints"][0]["status"] == "WITNESSED"
    assert len(list((tmp_path / "share" / ORG).glob("*.json"))) == 1
    again = admin.post(f"/v1/{ORG}/anchors/run").json()
    assert again["created"] is False and "Nothing new" in again["message"]
    exp = admin.get(f"/v1/{ORG}/anchors/export")
    assert len(exp.text.strip().splitlines()) == 1 and json.loads(exp.text)["signature"]
    assert "public_key:" in admin.get(f"/v1/{ORG}/anchors/pubkey").text


def test_only_a_compliance_administrator_can_force_a_checkpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_ANCHOR_DIR", str(tmp_path / "share"))
    reset_manager()
    seed(1)
    assert client(UserRole.AUDITOR, "aud").post(f"/v1/{ORG}/anchors/run").status_code == 403


def test_the_health_card_reports_anchoring_and_only_the_banner_to_others(tmp_path, monkeypatch):
    seed(1)
    admin = client(UserRole.SUPER_ADMIN, "root")
    assert admin.get("/api/system/health").json()["checks"]["anchoring"]["status"] == "disabled"
    monkeypatch.setenv("VERITAS_ANCHOR_DIR", str(tmp_path / "share"))
    reset_manager()
    h = admin.get("/api/system/health").json()["checks"]["anchoring"]
    assert h["status"] == "error" and h["banner"] is True              # records exist and nothing is witnessed yet
    client(UserRole.COMPLIANCE_ADMIN, "adm").post(f"/v1/{ORG}/anchors/run")
    h = admin.get("/api/system/health").json()["checks"]["anchoring"]
    assert h["status"] == "ok" and h["banner"] is False and h["single_witness"] is True
    viewer = client(UserRole.VIEWER, "view").get("/api/system/health").json()["checks"]["anchoring"]
    assert set(viewer) == {"status", "banner"}
