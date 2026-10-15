"""GET /metrics: a bearer token chosen by the administrator, never a user session."""
import pytest
from fastapi.testclient import TestClient

import agent_store.store as agent_store_module
import evidence_store.store as store_module
import user_store.store as user_store_module
from agent_store.store import reset_agent_store
from dashboard.server import app
from evidence_store.store import reset_store
from rate_limit import _limiter
from user_store.models import UserRole
from user_store.store import get_user_store, reset_user_store

TOKEN = "scrape-token-for-tests-12345"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "_DEFAULT_DB_PATH", tmp_path / "m_evidence.db")
    monkeypatch.setattr(agent_store_module, "_DEFAULT_DB_PATH", tmp_path / "m_agents.db")
    monkeypatch.setattr(user_store_module, "_DEFAULT_DB_PATH", tmp_path / "m_users.db")
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VERITAS_SECURE_COOKIES", "false")
    monkeypatch.setenv("VERITAS_JWT_SECRET", "metrics-test-secret-key-metrics-test-secret")
    reset_store(); reset_agent_store(); reset_user_store(); _limiter._windows.clear()
    yield
    reset_store(); reset_agent_store(); reset_user_store(); _limiter._windows.clear()


def test_metrics_are_off_without_a_token(monkeypatch):
    monkeypatch.delenv("VERITAS_METRICS_TOKEN", raising=False)
    c = TestClient(app, raise_server_exceptions=False)
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 401


def test_the_right_token_gets_numbers(monkeypatch):
    monkeypatch.setenv("VERITAS_METRICS_TOKEN", TOKEN)
    r = TestClient(app, raise_server_exceptions=False).get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert "veritas_scrape_timestamp_seconds" in r.text


def test_a_wrong_token_and_a_user_session_are_refused(monkeypatch):
    monkeypatch.setenv("VERITAS_METRICS_TOKEN", TOKEN)
    from passlib.context import CryptContext
    pw = CryptContext(schemes=["bcrypt"], deprecated="auto").hash("AdminPass1!")
    get_user_store().create_user("m_admin", "m@test.io", pw, UserRole.SUPER_ADMIN)
    c = TestClient(app, raise_server_exceptions=False)
    assert c.post("/api/auth/login", data={"username": "m_admin", "password": "AdminPass1!"}).status_code == 200
    assert c.get("/metrics").status_code == 401                                     # a session is not the token
    assert c.get("/metrics", headers={"Authorization": "Bearer nope-nope-nope-nope"}).status_code == 401
