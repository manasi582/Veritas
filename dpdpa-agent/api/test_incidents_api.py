"""The incident endpoints: who may use them, what they return, and that a status change is a chained event."""
import pytest
from fastapi.testclient import TestClient

from api.test_anchors_api import ORG, client, isolated  # noqa: F401  (the fixture and helpers are shared)
from evidence_store.store import get_store
from evidence_store.test_evidence_store import _make_explained_verdict
from incidents.template import template_of
from user_store.models import UserRole


def seed(n=3, line="timeout calling payments after 30s"):
    for _ in range(n):
        get_store().append(_make_explained_verdict(tenant_id=ORG), grouping=tuple(template_of(line)))


def one_incident():
    (row,), _ = get_store().list_incidents(ORG)
    return row["incident_id"]


def test_the_list_summary_and_one_incident(monkeypatch):
    seed(5)
    v = client(UserRole.VIEWER, "view")
    body = v.get(f"/v1/{ORG}/incidents").json()
    assert body["total"] == 1 and body["incidents"][0]["count"] == 5 and len(body["incidents"][0]["sparkline"]) == 24
    assert v.get(f"/v1/{ORG}/incidents/summary").json()["verdicts"] == 5
    iid = body["incidents"][0]["incident_id"]
    assert v.get(f"/v1/{ORG}/incidents/{iid}").json()["template"].startswith("timeout calling")
    assert len(v.get(f"/v1/{ORG}/incidents/{iid}/verdicts").json()["verdicts"]) == 5
    assert v.get(f"/v1/{ORG}/incidents/nope").status_code == 404


def test_filters(monkeypatch):
    seed(2)
    v = client(UserRole.VIEWER, "view")
    assert v.get(f"/v1/{ORG}/incidents?status=RESOLVED").json()["total"] == 0
    assert v.get(f"/v1/{ORG}/incidents?status=OPEN&severity=HIGH").json()["total"] == 1
    assert v.get(f"/v1/{ORG}/incidents?source_system=nothing").json()["total"] == 0


def test_only_a_compliance_admin_may_change_an_incident():
    seed(2)
    iid = one_incident()
    for role, name in ((UserRole.VIEWER, "v"), (UserRole.AUDITOR, "a")):
        c = client(role, name)
        assert c.post(f"/v1/{ORG}/incidents/{iid}/status", json={"status": "RESOLVED"}).status_code == 403
        assert c.post(f"/v1/{ORG}/incidents/{iid}/merge", json={"merge_from": "x"}).status_code == 403
        assert c.post(f"/v1/{ORG}/incidents/{iid}/split", json={"verdict_ids": ["x"]}).status_code == 403
    assert get_store().get_incident(ORG, iid)["status"] == "OPEN"


def test_resolve_writes_a_chained_event_with_the_actor():
    seed(2)
    iid = one_incident()
    admin = client(UserRole.COMPLIANCE_ADMIN, "adm")
    r = admin.post(f"/v1/{ORG}/incidents/{iid}/status", json={"status": "ACKNOWLEDGED", "reason": "on it"})
    assert r.status_code == 200 and r.json()["incident"]["status"] == "ACKNOWLEDGED"
    assert admin.post(f"/v1/{ORG}/incidents/{iid}/status", json={"status": "OPEN"}).status_code == 400
    assert get_store().verify_chain(ORG)["valid"] is True
    n = get_store()._conn.execute("SELECT COUNT(*) AS n FROM evidence WHERE record_type = 'INCIDENT_EVENT'").fetchone()["n"]
    assert n == 1


def test_split_and_merge_through_the_api():
    seed(4)
    iid = one_incident()
    admin = client(UserRole.COMPLIANCE_ADMIN, "adm")
    vids = [v["verdict_id"] for v in admin.get(f"/v1/{ORG}/incidents/{iid}/verdicts").json()["verdicts"]]
    new = admin.post(f"/v1/{ORG}/incidents/{iid}/split", json={"verdict_ids": vids[:1]}).json()["incident"]
    assert new["count"] == 1
    merged = admin.post(f"/v1/{ORG}/incidents/{iid}/merge", json={"merge_from": new["incident_id"]}).json()["incident"]
    assert merged["count"] == 4
    assert admin.get(f"/v1/{ORG}/incidents").json()["total"] == 1


def test_the_owner_of_a_system_is_shown_with_its_incidents(monkeypatch):
    seed(1)
    from api import incidents as api_inc
    monkeypatch.setattr(api_inc, "_owners", lambda org: {"order-service": {"team": "Payments", "email": "pay@x.io",
                                                                          "slack_channel": "#pay"}})
    body = client(UserRole.VIEWER, "view").get(f"/v1/{ORG}/incidents").json()
    assert body["incidents"][0]["owner"]["team"] == "Payments"
