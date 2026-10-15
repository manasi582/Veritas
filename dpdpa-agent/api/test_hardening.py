"""
Web-application hardening checks beyond the route and role tests: file names that try to escape a
folder, cross-site requests, and error responses that must not reveal the server's insides.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import agent_store.store as agent_store_module
import evidence_store.store as store_module
import user_store.store as user_store_module
from agent_store.store import reset_agent_store
from dashboard import live_feed
from dashboard.server import app
from evidence_store.store import reset_store
from rate_limit import _limiter
from user_store.models import UserRole
from user_store.store import get_user_store, reset_user_store


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "_DEFAULT_DB_PATH", tmp_path / "h_evidence.db")
    monkeypatch.setattr(agent_store_module, "_DEFAULT_DB_PATH", tmp_path / "h_agents.db")
    monkeypatch.setattr(user_store_module, "_DEFAULT_DB_PATH", tmp_path / "h_users.db")
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VERITAS_SECURE_COOKIES", "false")
    monkeypatch.setenv("VERITAS_JWT_SECRET", "hardening-test-secret-key")
    reset_store(); reset_agent_store(); reset_user_store()
    live_feed._ws_clients.clear(); _limiter._windows.clear()
    yield
    reset_store(); reset_agent_store(); reset_user_store()
    live_feed._ws_clients.clear(); _limiter._windows.clear()


@pytest.fixture()
def admin_client():
    from passlib.context import CryptContext
    pw_hash = CryptContext(schemes=["bcrypt"], deprecated="auto").hash("AdminPass1!")
    get_user_store().create_user("h_admin", "h@test.io", pw_hash, UserRole.SUPER_ADMIN)
    c = TestClient(app, raise_server_exceptions=False)
    assert c.post("/api/auth/login", data={"username": "h_admin", "password": "AdminPass1!"}).status_code == 200
    return c


class TestBackupFileNamesCannotEscapeTheBackupFolder:

    @pytest.mark.parametrize("name", [
        "../secrets/db.key", "..%2Fsecrets%2Fdb.key", "/etc/passwd", "a/b.zip", "..\\x.zip", "..", ".",
    ])
    def test_a_path_is_refused_not_looked_up(self, admin_client, name):
        r = admin_client.post("/api/system/backup/verify", params={"filename": name})
        assert r.status_code in (400, 404, 422)
        assert r.status_code != 200
        assert "no such file" not in r.text.lower()

    def test_a_path_and_a_missing_name_are_told_apart_only_by_the_instruction_not_by_the_file_system(self, admin_client):
        # a name that does not exist and a path that does exist elsewhere must not look different
        missing = admin_client.post("/api/system/backup/verify", params={"filename": "nope.zip"})
        assert missing.status_code == 404
        escape = admin_client.post("/api/system/backup/verify", params={"filename": "../h_users.db"})
        assert escape.status_code == 400


class TestCrossSiteRequests:

    def test_another_website_gets_no_cross_origin_permission(self, admin_client):
        r = admin_client.get("/api/auth/me", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in {k.lower() for k in r.headers}

    def test_a_cross_site_preflight_is_not_approved(self, admin_client):
        r = admin_client.options("/api/auth/users", headers={
            "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        assert r.headers.get("access-control-allow-origin") is None

    def test_the_session_cookie_is_not_sent_cross_site(self, anon_client_login):
        set_cookie = anon_client_login.headers.get("set-cookie", "").lower()
        assert "samesite=lax" in set_cookie or "samesite=strict" in set_cookie
        assert "httponly" in set_cookie


@pytest.fixture()
def anon_client_login():
    from passlib.context import CryptContext
    pw_hash = CryptContext(schemes=["bcrypt"], deprecated="auto").hash("AdminPass1!")
    get_user_store().create_user("h_admin2", "h2@test.io", pw_hash, UserRole.SUPER_ADMIN)
    return TestClient(app, raise_server_exceptions=False).post(
        "/api/auth/login", data={"username": "h_admin2", "password": "AdminPass1!"})


class TestErrorsRevealNothingInternal:

    def test_a_malformed_body_does_not_leak_a_traceback_or_a_path(self, admin_client):
        r = admin_client.post("/api/auth/users", content=b"{not json", headers={"Content-Type": "application/json"})
        assert r.status_code in (400, 422)
        for secret in ("Traceback", "site-packages", "/Users/", "/opt/veritas", ".py\""):
            assert secret not in r.text

    def test_an_unknown_path_is_a_plain_json_404(self, admin_client):
        r = admin_client.get("/api/does/not/exist")
        assert r.status_code == 404
        assert "Traceback" not in r.text
