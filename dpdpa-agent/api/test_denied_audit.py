"""A refused request is audited as DENIED with who, which route and the role; the caller's address is recorded and a forwarded
address is believed only behind a trusted proxy."""
from fastapi.testclient import TestClient

from api.test_anchors_api import ORG, client, isolated  # noqa: F401
from api import auth_deps
from audit_log.store import get_audit_store
from dashboard.server import app
from evidence_store.store import get_store
from evidence_store.test_evidence_store import _make_explained_verdict
from user_store.models import UserRole


def denials():
    return [e for e in get_audit_store().query(limit=200) if e["action"] == "ACCESS_DENIED"]


def test_a_refused_request_is_audited_as_denied_with_route_role_and_address():
    auth_deps._DENIAL_SEEN.clear()
    get_store().append(_make_explained_verdict(tenant_id=ORG))
    v = client(UserRole.VIEWER, "viewer_x")
    assert v.get(f"/v1/{ORG}/audit-pack").status_code == 403
    assert v.post(f"/v1/{ORG}/rules/changes", json={"kind": "OVERLAY"}).status_code == 403
    d = [e for e in denials() if e["actor_name"] == "viewer_x"]
    assert {e["resource"] for e in d} == {f"GET /v1/{ORG}/audit-pack", f"POST /v1/{ORG}/rules/changes"}
    first = [e for e in d if e["resource"].endswith("/audit-pack")][0]
    assert first["result"] == "DENIED" and first["actor_name"] == "viewer_x" and first["ip_address"]
    assert '"role": "VIEWER"' in str(first["detail"]) or first["detail"]["role"] == "VIEWER"


def test_the_lookup_denial_is_denied_not_success():
    auth_deps._DENIAL_SEEN.clear()
    v = client(UserRole.VIEWER, "viewer_y")
    assert v.post(f"/v1/{ORG}/subjects/lookup", json={"category": "phone", "identifier": "9876543210"}).status_code == 403
    e = [x for x in denials() if x["resource"].endswith("/subjects/lookup")]
    assert e and all(x["result"] == "DENIED" for x in e)
    assert not [x for x in get_audit_store().query(limit=200) if x["action"] == "SUBJECT_LOOKUP"]


def test_repeated_refusals_are_not_all_logged():
    auth_deps._DENIAL_SEEN.clear()
    v = client(UserRole.VIEWER, "viewer_z")
    for _ in range(25):
        v.get(f"/v1/{ORG}/audit-pack")
    assert len([e for e in denials() if e["actor_name"] == "viewer_z"]) == 1


def test_allowed_requests_leave_no_denial():
    auth_deps._DENIAL_SEEN.clear()
    before = len(denials())
    client(UserRole.AUDITOR, "aud_ok").get(f"/v1/{ORG}/rules")
    assert len(denials()) == before


def test_forwarded_address_is_ignored_unless_a_proxy_is_trusted(monkeypatch):
    auth_deps._DENIAL_SEEN.clear()
    monkeypatch.delenv("VERITAS_TRUSTED_PROXY", raising=False)
    v = client(UserRole.VIEWER, "viewer_p")
    v.get(f"/v1/{ORG}/audit-pack", headers={"X-Forwarded-For": "203.0.113.9"})
    mine = [e for e in denials() if e["actor_name"] == "viewer_p"]
    assert mine and mine[0]["ip_address"] != "203.0.113.9"
    auth_deps._DENIAL_SEEN.clear()
    monkeypatch.setenv("VERITAS_TRUSTED_PROXY", "true")
    v.get(f"/v1/{ORG}/audit-pack", headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"})
    assert "203.0.113.9" in {e["ip_address"] for e in denials() if e["actor_name"] == "viewer_p"}


def test_the_rate_limiter_does_not_trust_a_forwarded_address_by_default(monkeypatch):
    from starlette.requests import Request
    from rate_limit import _client_ip
    scope = {"type": "http", "headers": [(b"x-forwarded-for", b"203.0.113.77")], "client": ("10.1.2.3", 5000), "method": "GET", "path": "/", "query_string": b""}
    monkeypatch.delenv("VERITAS_TRUSTED_PROXY", raising=False)
    assert _client_ip(Request(scope)) == "10.1.2.3"
    monkeypatch.setenv("VERITAS_TRUSTED_PROXY", "true")
    assert _client_ip(Request(scope)) == "203.0.113.77"
