"""
Route-access tests (Phase C, C1).

Every route of the API is listed from its schema and checked against a reviewed
declaration of who may use it:

  * a route that is not on the PUBLIC list must answer an anonymous caller with exactly 401;
  * a route that changes something must refuse every role below its declared minimum
    (viewers are read-only) and let the minimum role through;
  * a route inside an organization must refuse people outside that organization;
  * the live-feed WebSocket follows the same rules as the HTTP API;
  * the few public endpoints reveal nothing internal.

A new route that is not declared here makes these tests FAIL on purpose: its access must be
decided and written down, so a route can never become reachable by accident.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import agent_store.store as agent_store_module
import evidence_store.store as store_module
import user_store.store as user_store_module
from agent_store.store import reset_agent_store
from dashboard import live_feed
from dashboard.server import app
from rate_limit import _limiter
from user_store.models import UserRole
from user_store.store import get_user_store, reset_user_store

client = TestClient(app, raise_server_exceptions=False)

OWN_ORG = "retail_co"      # organizations provided by conftest.py
OTHER_ORG = "edtech_co"

# ---------------------------------------------------------------------------
# The reviewed declarations
# ---------------------------------------------------------------------------

# Reachable without a login, on purpose.
PUBLIC = {
    ("GET", "/"):                  "dashboard page (a shell; its data calls need a login)",
    ("GET", "/login"):             "login page",
    ("GET", "/setup"):             "first-run setup page",
    ("GET", "/health"):            "liveness probe",
    ("GET", "/ready"):             "readiness probe (reports ok/error only)",
    ("GET", "/api/version"):       "API version only",
    ("GET", "/api/tls/cert"):      "agents fetch the server certificate before they can trust it",
    ("POST", "/api/auth/login"):   "login",
    ("POST", "/api/auth/setup"):   "creates the first administrator, only while no user exists",
    ("POST", "/agent/register"):   "authenticated by the one-time registration key in the body",
}

# Authenticated by an agent token instead of a user session.
AGENT_TOKEN_ROUTES = {
    ("POST", "/agent/heartbeat"),
    ("POST", "/v1/{org_id}/events"),
    ("POST", "/v1/{org_id}/otlp/logs"),
    ("GET", "/metrics"),            # a bearer token chosen by the administrator (VERITAS_METRICS_TOKEN)
}

# Routes that change something: the lowest role allowed to use each.
VIEWER, AUDITOR, COMPLIANCE_ADMIN, SUPER_ADMIN = (
    UserRole.VIEWER, UserRole.AUDITOR, UserRole.COMPLIANCE_ADMIN, UserRole.SUPER_ADMIN)
ROLE_ORDER = [VIEWER, AUDITOR, COMPLIANCE_ADMIN, SUPER_ADMIN]

MUTATING_MIN_ROLE = {
    ("POST", "/v1/{org_id}/anchors/run"):                    COMPLIANCE_ADMIN,
    ("POST", "/v1/{org_id}/retention/tasks"):                COMPLIANCE_ADMIN,
    ("POST", "/v1/{org_id}/policy-packs/{pack_id}/preview"): AUDITOR,
    ("POST", "/v1/{org_id}/policy-packs/{pack_id}/apply"):   COMPLIANCE_ADMIN,
    ("POST", "/v1/{org_id}/subjects/lookup"):                COMPLIANCE_ADMIN,
    ("POST", "/v1/{org_id}/requests"):                       COMPLIANCE_ADMIN,
    ("POST", "/v1/{org_id}/requests/{request_id}/tasks/{system}/confirm"): COMPLIANCE_ADMIN,
    ("POST", "/v1/{org_id}/requests/{request_id}/close"):    COMPLIANCE_ADMIN,
    ("POST", "/v1/{org_id}/subjects/keys/rotate"):           COMPLIANCE_ADMIN,
    ("POST", "/v1/{org_id}/subjects/keys/retire"):           COMPLIANCE_ADMIN,
    ("POST", "/v1/{org_id}/incidents/{incident_id}/status"): COMPLIANCE_ADMIN,
    ("POST", "/v1/{org_id}/incidents/{incident_id}/merge"):  COMPLIANCE_ADMIN,
    ("POST", "/v1/{org_id}/incidents/{incident_id}/split"):  COMPLIANCE_ADMIN,
    ("POST", "/agents/issue-key"):                           COMPLIANCE_ADMIN,
    ("POST", "/agents/keys/{key_id}/revoke"):                COMPLIANCE_ADMIN,
    ("POST", "/agents/{agent_id}/revoke"):                   COMPLIANCE_ADMIN,
    ("POST", "/api/auth/users"):                             SUPER_ADMIN,
    ("PATCH", "/api/auth/users/{user_id}"):                  SUPER_ADMIN,
    ("POST", "/api/auth/users/{user_id}/reset-password"):    SUPER_ADMIN,
    ("POST", "/api/auth/users/{user_id}/orgs/{org_id}"):     SUPER_ADMIN,
    ("DELETE", "/api/auth/users/{user_id}/orgs/{org_id}"):   SUPER_ADMIN,
    ("POST", "/api/system/backup"):                          SUPER_ADMIN,
    ("POST", "/api/system/backup/verify"):                   SUPER_ADMIN,
    ("PATCH", "/api/{org_id}/verdicts/{verdict_id}/case"):   COMPLIANCE_ADMIN,
    ("POST", "/api/{org_id}/verdicts/{verdict_id}/comments"): AUDITOR,
    ("POST", "/api/{org_id}/verdicts/{verdict_id}/status"):  COMPLIANCE_ADMIN,
    ("POST", "/v1/orgs/{org_id}/config"):                    COMPLIANCE_ADMIN,
    ("POST", "/v1/{org_id}/investigate"):                    AUDITOR,
    ("POST", "/v1/{org_id}/scan"):                           AUDITOR,
}
# Any logged-in user may end their own session and change their own password.
ANY_USER_MUTATING = {("POST", "/api/auth/logout"), ("POST", "/api/auth/change-password")}

# Read-only routes that need more than a plain login.
READ_MIN_ROLE = {
    ("GET", "/agents/keys"):                      COMPLIANCE_ADMIN,
    ("GET", "/api/audit/logs"):                   SUPER_ADMIN,
    ("GET", "/api/auth/users"):                   SUPER_ADMIN,
    ("GET", "/api/auth/users/{user_id}/orgs"):    SUPER_ADMIN,
    ("GET", "/api/system/backups"):               SUPER_ADMIN,
    ("GET", "/api/{org_id}/evidence/export"):     AUDITOR,
    ("GET", "/v1/{org_id}/requests"):             AUDITOR,
    ("GET", "/v1/{org_id}/requests/{request_id}"): AUDITOR,
    ("GET", "/v1/{org_id}/requests/{request_id}/record.json"): AUDITOR,
    ("GET", "/v1/{org_id}/requests/{request_id}/record.pdf"): AUDITOR,
    ("GET", "/v1/{org_id}/subjects/keys"):        AUDITOR,
    ("GET", "/v1/{org_id}/anchors"):              AUDITOR,
    ("GET", "/v1/{org_id}/anchors/export"):       AUDITOR,
    ("GET", "/v1/{org_id}/anchors/pubkey"):       AUDITOR,
    ("GET", "/v1/{org_id}/evidence/export"):      AUDITOR,
}

MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def schema_routes():
    out = []
    for path, ops in app.openapi()["paths"].items():
        for method in ops:
            if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                out.append((method.upper(), path))
    return sorted(out)


def url_for(path: str, org: str = OWN_ORG) -> str:
    url = path.replace("{org_id}", org)
    return re.sub(r"\{[^}]+\}", "x", url)


def body_for(method: str, path: str):
    if method not in MUTATING_METHODS:
        return None
    if path == "/agent/heartbeat":
        return {"agent_id": "x"}
    if path == "/v1/{org_id}/events":
        return {"source_type": "log", "source_system": "s", "raw_snippet": "x"}
    return {}


def call(c: TestClient, method: str, path: str, org: str = OWN_ORG) -> int:
    return c.request(method, url_for(path, org), json=body_for(method, path)).status_code


def make_client(role: UserRole, orgs=(), name: str = "u") -> TestClient:
    from passlib.context import CryptContext
    pw = CryptContext(schemes=["bcrypt"], deprecated="auto").hash("testpass123!")
    user = get_user_store().create_user(name, f"{name}@test.io", pw, role)
    for org in orgs:
        get_user_store().grant_org_access(user.user_id, org)
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/auth/login", data={"username": name, "password": "testpass123!"})
    assert r.status_code == 200, r.text
    c.user_id = user.user_id
    return c


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "_DEFAULT_DB_PATH", tmp_path / "evidence.db")
    monkeypatch.setattr(agent_store_module, "_DEFAULT_DB_PATH", tmp_path / "agents.db")
    monkeypatch.setattr(user_store_module, "_DEFAULT_DB_PATH", tmp_path / "users.db")
    monkeypatch.setenv("VERITAS_SECURE_COOKIES", "false")
    monkeypatch.setenv("VERITAS_JWT_SECRET", "test-jwt-secret-for-unit-tests-only")
    store_module.reset_store()
    reset_agent_store()
    reset_user_store()
    live_feed._ws_clients.clear()
    _limiter._windows.clear()
    yield
    store_module.reset_store()
    reset_agent_store()
    reset_user_store()
    live_feed._ws_clients.clear()
    _limiter._windows.clear()


# ---------------------------------------------------------------------------
# 1. Every route is declared, and anonymous callers are refused
# ---------------------------------------------------------------------------

class TestEveryRouteIsDeclared:

    def test_declarations_match_the_routes_that_exist(self):
        existing = set(schema_routes())
        declared = (set(PUBLIC) | AGENT_TOKEN_ROUTES | set(MUTATING_MIN_ROLE)
                    | ANY_USER_MUTATING | set(READ_MIN_ROLE))
        stale = declared - existing
        assert not stale, f"declared but no longer existing (remove from the tables): {sorted(stale)}"

    def test_every_route_that_changes_something_has_a_declared_minimum_role(self):
        undeclared = [
            (m, p) for m, p in schema_routes()
            if m in MUTATING_METHODS
            and (m, p) not in PUBLIC and (m, p) not in AGENT_TOKEN_ROUTES
            and (m, p) not in MUTATING_MIN_ROLE and (m, p) not in ANY_USER_MUTATING
        ]
        assert not undeclared, (
            f"New route(s) that change data have no declared access: {undeclared}. "
            "Add each to MUTATING_MIN_ROLE with the lowest role that may use it.")

    @pytest.mark.parametrize("method,path", [r for r in schema_routes() if r not in PUBLIC],
                             ids=lambda v: v if isinstance(v, str) else None)
    def test_anonymous_callers_get_exactly_401(self, method, path):
        code = call(client, method, path)
        assert code == 401, f"{method} {path} answered {code} to an anonymous caller (want 401)"

    def test_the_public_routes_really_are_the_only_open_ones(self):
        open_routes = []
        for method, path in schema_routes():
            if (method, path) in PUBLIC:
                continue
            if call(client, method, path) != 401:
                open_routes.append((method, path))
        assert open_routes == []


# ---------------------------------------------------------------------------
# 2. Roles
# ---------------------------------------------------------------------------

def _mutating_cases():
    return sorted(MUTATING_MIN_ROLE.items(), key=lambda kv: kv[0])


class TestRolesOnRoutesThatChangeSomething:

    @pytest.mark.parametrize("route,minimum", _mutating_cases(), ids=lambda v: f"{v[0]} {v[1]}" if isinstance(v, tuple) else None)
    def test_roles_below_the_minimum_are_refused(self, route, minimum):
        method, path = route
        for role in ROLE_ORDER[:ROLE_ORDER.index(minimum)]:
            c = make_client(role, orgs=(OWN_ORG,), name=f"low_{role.value.lower()}")
            assert call(c, method, path) == 403, f"{role.value} must be refused on {method} {path}"

    @pytest.mark.parametrize("route,minimum", _mutating_cases(), ids=lambda v: f"{v[0]} {v[1]}" if isinstance(v, tuple) else None)
    def test_the_minimum_role_gets_past_the_access_check(self, route, minimum):
        method, path = route
        orgs = () if minimum == SUPER_ADMIN else (OWN_ORG,)
        c = make_client(minimum, orgs=orgs, name="minimum")
        # 4xx other than 401/403 (validation, not found) means the access check passed.
        assert call(c, method, path) not in (401, 403), f"{minimum.value} must be allowed on {method} {path}"

    def test_viewers_cannot_change_anything_at_all(self):
        viewer = make_client(VIEWER, orgs=(OWN_ORG,), name="readonly")
        for method, path in schema_routes():
            if method not in MUTATING_METHODS or (method, path) in PUBLIC \
                    or (method, path) in AGENT_TOKEN_ROUTES or (method, path) in ANY_USER_MUTATING:
                continue
            assert call(viewer, method, path) == 403, f"a viewer reached {method} {path}"

    @pytest.mark.parametrize("route,minimum", sorted(READ_MIN_ROLE.items()), ids=lambda v: f"{v[0]} {v[1]}" if isinstance(v, tuple) else None)
    def test_restricted_read_routes(self, route, minimum):
        method, path = route
        for role in ROLE_ORDER[:ROLE_ORDER.index(minimum)]:
            c = make_client(role, orgs=(OWN_ORG,), name=f"rlow_{role.value.lower()}")
            assert call(c, method, path) == 403, f"{role.value} must be refused on {method} {path}"
        orgs = () if minimum == SUPER_ADMIN else (OWN_ORG,)
        ok = make_client(minimum, orgs=orgs, name="rmin")
        assert call(ok, method, path) not in (401, 403), f"{minimum.value} must be allowed on {method} {path}"

    def test_every_logged_in_user_can_end_their_own_session(self):
        c = make_client(VIEWER, name="leaver")
        assert c.post("/api/auth/logout").status_code == 200


# ---------------------------------------------------------------------------
# 3. Organization boundaries
# ---------------------------------------------------------------------------

def _org_routes():
    return [(m, p) for m, p in schema_routes()
            if "{org_id}" in p and (m, p) not in AGENT_TOKEN_ROUTES and (m, p) not in PUBLIC]


class TestOrganizationBoundaries:

    @pytest.mark.parametrize("method,path", _org_routes(), ids=lambda v: v if isinstance(v, str) else None)
    def test_a_user_in_no_organization_is_refused(self, method, path):
        c = make_client(VIEWER, orgs=(), name="nobody")
        assert call(c, method, path) in (403, 404), f"{method} {path} served a user with no organization"

    @pytest.mark.parametrize("method,path", _org_routes(), ids=lambda v: v if isinstance(v, str) else None)
    def test_an_administrator_of_one_organization_is_refused_in_another(self, method, path):
        c = make_client(COMPLIANCE_ADMIN, orgs=(OWN_ORG,), name="other_admin")
        assert call(c, method, path, org=OTHER_ORG) in (403, 404), \
            f"{method} {path} let an administrator of {OWN_ORG} into {OTHER_ORG}"

    def test_super_admin_reaches_every_organization(self):
        c = make_client(SUPER_ADMIN, name="boss")
        assert call(c, "GET", "/api/{org_id}/verdicts", org=OTHER_ORG) == 200


# ---------------------------------------------------------------------------
# 4. The live-feed WebSocket follows the same rules
# ---------------------------------------------------------------------------

def _ws_result(c: TestClient, org: str):
    try:
        with c.websocket_connect(f"/ws/{org}"):
            return "connected"
    except WebSocketDisconnect as e:
        return e.code


class TestLiveFeedWebSocket:

    def test_no_session_is_refused(self):
        assert _ws_result(TestClient(app), OWN_ORG) == 4001

    def test_a_user_in_no_organization_is_refused(self):
        assert _ws_result(make_client(VIEWER, name="nobody"), OWN_ORG) == 4003

    def test_a_member_of_another_organization_is_refused(self):
        assert _ws_result(make_client(VIEWER, orgs=(OTHER_ORG,), name="elsewhere"), OWN_ORG) == 4003

    def test_a_member_can_watch_their_own_organization(self):
        assert _ws_result(make_client(VIEWER, orgs=(OWN_ORG,), name="member"), OWN_ORG) == "connected"

    def test_super_admin_can_watch_any_organization(self):
        assert _ws_result(make_client(SUPER_ADMIN, name="boss"), OTHER_ORG) == "connected"

    def test_a_disabled_account_with_an_old_session_is_refused(self):
        c = make_client(VIEWER, orgs=(OWN_ORG,), name="soon_disabled")
        assert _ws_result(c, OWN_ORG) == "connected"
        get_user_store().set_active(c.user_id, False)
        assert c.get("/api/auth/me").status_code == 403, "HTTP already refuses a disabled account"
        assert _ws_result(c, OWN_ORG) == 4003, "the WebSocket must refuse it too"

    def test_a_forged_session_is_refused(self):
        c = TestClient(app)
        c.cookies.set("veritas_session", "not-a-real-token")
        assert _ws_result(c, OWN_ORG) == 4001


# ---------------------------------------------------------------------------
# 5. Agent-token routes
# ---------------------------------------------------------------------------

class TestAgentTokenRoutes:

    @pytest.mark.parametrize("method,path", sorted(AGENT_TOKEN_ROUTES))
    def test_missing_and_wrong_tokens_are_refused(self, method, path):
        assert call(client, method, path) == 401
        r = client.request(method, url_for(path), json=body_for(method, path),
                           headers={"Authorization": "Bearer not-a-real-token"})
        assert r.status_code == 401

    def test_a_user_session_is_not_an_agent_token(self):
        admin = make_client(SUPER_ADMIN, name="boss")
        assert call(admin, "POST", "/v1/{org_id}/events") == 401


# ---------------------------------------------------------------------------
# 6. Public endpoints reveal nothing internal
# ---------------------------------------------------------------------------

class TestPublicEndpointsRevealNothingInternal:

    def test_ready_reports_only_ok_or_error_words(self):
        body = client.get("/ready").json()
        assert set(body) == {"ready", "checks"}
        assert set(body["checks"].values()) <= {"ok", "error", "valid", "invalid"}
        text = client.get("/ready").text
        assert ".vlic" not in text and "/" not in body["checks"].get("license", ""), "no file paths or error text"

    def test_version_endpoint_gives_only_the_version(self):
        assert set(client.get("/api/version").json()) == {"api_version", "service"}

    def test_api_schema_requires_a_login(self):
        assert client.get("/api/openapi.json").status_code == 401
        c = make_client(VIEWER, name="reader")
        r = c.get("/api/openapi.json")
        assert r.status_code == 200 and "/agents/issue-key" in r.json()["paths"]

    def test_interactive_docs_are_off(self):
        assert client.get("/docs").status_code == 404 and client.get("/redoc").status_code == 404

    def test_license_details_require_a_login(self):
        assert client.get("/api/license").status_code == 401


class TestSystemHealthIsScopedAndRedacted:

    def test_agent_count_covers_only_the_users_own_organizations(self):
        from agent_store.store import get_agent_store
        store = get_agent_store()
        for org in (OWN_ORG, OWN_ORG, OTHER_ORG):
            store.create_agent(org, "a")
        viewer = make_client(VIEWER, orgs=(OWN_ORG,), name="counter")
        assert viewer.get("/api/system/health").json()["checks"]["agent_store"]["agents"] == 2
        boss = make_client(SUPER_ADMIN, name="boss")
        assert boss.get("/api/system/health").json()["checks"]["agent_store"]["agents"] == 3

    def test_server_level_detail_is_only_for_the_administrator(self):
        viewer = make_client(VIEWER, orgs=(OWN_ORG,), name="curious")
        checks = viewer.get("/api/system/health").json()["checks"]
        assert set(checks) <= {"evidence_store", "agent_store", "license", "tls", "disk", "runtime", "anchoring"}
        assert set(checks.get("anchoring", {})) <= {"status", "banner"}      # only whether to warn, never where witnesses are
        text = str(checks)
        for secret in ("detail", "fingerprint", "python", "platform", "secrets", "files"):
            assert secret not in text, f"'{secret}' must not reach a non-administrator"
        boss = make_client(SUPER_ADMIN, name="boss")
        full = boss.get("/api/system/health").json()["checks"]
        assert "secrets" in full and "ai" in full and "python" in full["runtime"]
