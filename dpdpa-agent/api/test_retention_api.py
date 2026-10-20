"""Retention review through the API (phase D): who may read and who may open tasks, and the whole loop."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from api.test_anchors_api import ORG, client, isolated  # noqa: F401
from evidence_store.store import get_store
from org_config.schema import OrgConfig
from user_store.models import UserRole


def policy(days=30):
    return OrgConfig.model_validate({"org_id": ORG, "fields": [
        {"field_name": "phone", "pii_category": "phone", "declared_purpose": "calls", "consent_scope": "c", "retention_days": days,
         "source_system": "support"},
        {"field_name": "email", "pii_category": "email", "declared_purpose": "x", "consent_scope": "c", "retention_days": 365,
         "source_system": "billing"}],
        "owners": {"support": {"team": "Support", "email": "support@example.org"}}})


@pytest.fixture(autouse=True)
def with_policy(monkeypatch):
    from api import retention
    cfg = policy()
    monkeypatch.setattr(retention, "load_org_config", lambda org: cfg)
    import alerts  # noqa: F401
    now = datetime.now(timezone.utc)
    get_store().flows.record(ORG, "support", [("raw_snippet", "phone")], at=now - timedelta(days=45))
    get_store().flows.record(ORG, "support", [("raw_snippet", "phone")], at=now - timedelta(hours=3))
    get_store().flows.record(ORG, "billing", [("raw_snippet", "email")], at=now - timedelta(days=10))


def test_any_role_can_read_the_review(monkeypatch):
    body = client(UserRole.VIEWER, "view").get(f"/v1/{ORG}/retention").json()
    by = {i["system"]: i for i in body["items"]}
    assert by["support"]["status"] == "overdue" and by["support"]["owner"]["team"] == "Support" and by["billing"]["status"] == "within"
    assert body["summary"]["overdue"] == 1 and "never deletes" in body["note"]


def test_only_a_compliance_admin_opens_a_task():
    for role, name in ((UserRole.VIEWER, "v"), (UserRole.AUDITOR, "a")):
        assert client(role, name).post(f"/v1/{ORG}/retention/tasks", json={"systems": ["support"]}).status_code == 403


def test_the_loop_from_overdue_to_a_confirmed_task_to_overdue_again():
    c = client(UserRole.COMPLIANCE_ADMIN, "adm")
    r = c.post(f"/v1/{ORG}/retention/tasks", json={"systems": ["support"]})
    assert r.status_code == 201
    req = r.json()
    assert req["type"] == "retention" and req["tasks"][0]["owner"].startswith("Support")
    assert req["lookup"][0]["retention"][0]["field"] == "phone" and req["lookup"][0]["retention"][0]["status"] == "overdue"
    assert c.get(f"/v1/{ORG}/retention").json()["items"][0]["task_request_id"] == req["request_id"]
    assert c.post(f"/v1/{ORG}/retention/tasks", json={"systems": ["support"]}).status_code == 400           # already open
    done = c.post(f"/v1/{ORG}/requests/{req['request_id']}/tasks/support/confirm", json={"note": "purged"}).json()
    assert done["status"] == "CLOSED" and done["watching"] is False
    get_store().flows.record(ORG, "support", [("raw_snippet", "phone")])                                      # the data is still arriving
    item = c.get(f"/v1/{ORG}/retention").json()["items"][0]
    assert item["status"] == "overdue" and item["task_request_id"] is None
    assert get_store().verify_chain(ORG)["valid"] is True
    from audit_log.store import get_audit_store
    assert any(e["action"] == "RETENTION_TASK_CREATED" for e in get_audit_store().query(org_id=ORG))


def test_unknown_systems_and_empty_requests_are_refused():
    c = client(UserRole.COMPLIANCE_ADMIN, "adm")
    assert c.post(f"/v1/{ORG}/retention/tasks", json={"systems": ["nowhere"]}).status_code == 400
    assert c.post(f"/v1/{ORG}/retention/tasks", json={"systems": []}).status_code == 422


def test_the_task_record_downloads_and_is_titled_as_a_retention_record():
    c = client(UserRole.COMPLIANCE_ADMIN, "adm")
    rid = c.post(f"/v1/{ORG}/retention/tasks", json={"systems": ["support"]}).json()["request_id"]
    j = c.get(f"/v1/{ORG}/requests/{rid}/record.json").json()
    assert j["record"]["title"] == "Retention review record"
    assert c.get(f"/v1/{ORG}/requests/{rid}/record.pdf").content.startswith(b"%PDF")
