"""The map and record endpoints: any role of the organization may read them, nobody else, and they hold no values."""
import csv
import io

from api.test_anchors_api import ORG, client, isolated  # noqa: F401
from evidence_store.store import get_store
from evidence_store.test_flows import config
from user_store.models import UserRole


def setup_function(_):
    pass


def seed(monkeypatch):
    from api import flows as api_flows
    cfg = config()
    monkeypatch.setattr(api_flows, "load_org_config", lambda org: cfg)
    s = get_store()
    s.flows.record(ORG, "order-service", [("phone", "phone")], "analytics.vendor.io")
    s.flows.record(ORG, "marketing-service", [("raw_snippet", "aadhaar")])


def test_a_viewer_can_read_the_map(monkeypatch):
    seed(monkeypatch)
    body = client(UserRole.VIEWER, "view").get(f"/v1/{ORG}/flows").json()
    status = {n["id"]: n["status"] for n in body["nodes"]}
    assert status["order-service"] == "green" and status["marketing-service"] == "amber" and status["kyc-service"] == "grey"
    assert body["edges"][0]["target"] == "analytics.vendor.io" and "not a complete map" in body["note"]


def test_export_as_csv_and_json(monkeypatch):
    seed(monkeypatch)
    v = client(UserRole.VIEWER, "view")
    r = v.get(f"/v1/{ORG}/flows/export")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO("\n".join(l for l in r.text.splitlines() if not l.startswith("#")))))
    assert rows[0][0] == "record_type" and len(rows) > 3
    j = v.get(f"/v1/{ORG}/flows/export?format=json").json()
    assert j["title"] == "Record of observed processing" and j["rows"]
    assert v.get(f"/v1/{ORG}/flows/export?format=xml").status_code == 422


def test_a_user_without_access_to_the_organization_is_refused(monkeypatch):
    seed(monkeypatch)
    c = client(UserRole.VIEWER, "view")
    assert c.get("/v1/some_other_org/flows").status_code in (403, 404)
