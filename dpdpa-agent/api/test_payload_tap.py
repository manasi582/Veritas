"""The payload tap's events through the server (phase C): a field with personal data in an API payload is judged by the
policy as the field it is, and no value is ever seen by the server."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "veritas-sdk" / "python"))
import veritas_tap as vt  # noqa: E402

from api.test_agent_redaction import ORG, no_detection, post  # noqa: E402,F401
from api.test_agents import _register_agent, client as admin_client, isolated_stores  # noqa: E402,F401
from evidence_store import flows  # noqa: E402
from evidence_store.store import get_store  # noqa: E402

PHONE, AADHAAR = "9876543210", "2345 6789 0124"


def event_from_tap(body, route="/customers/42", status=200, direction="response"):
    tap = vt.Tap("http://127.0.0.1:1", "t", ORG, "customer-api", start=False, min_interval_seconds=0)
    tap.observe("GET", route, status, direction, json.dumps(body).encode())
    return tap.q.get_nowait()


def send(token, event):
    from fastapi.testclient import TestClient
    from dashboard.server import app
    return TestClient(app, raise_server_exceptions=False).post(
        f"/v1/{ORG}/events", headers={"Authorization": f"Bearer {token}"}, json=event)


@pytest.fixture
def token(no_detection):
    return _register_agent(ORG)[1]


def test_an_undeclared_field_in_a_payload_is_a_finding_for_that_field(token):
    r = send(token, event_from_tap({"user": {"aadhaar_no": AADHAAR}}))
    assert r.status_code == 200 and r.json()["contains_pii"] is True
    verdicts = r.json()["verdicts"]
    assert [v["field"] for v in verdicts] == ["user.aadhaar_no"] and verdicts[0]["rule_id"] == "PURPOSE_001"
    assert AADHAAR not in json.dumps(r.json()) and "2345" not in json.dumps(r.json())


def test_the_data_map_records_the_field_the_kind_and_that_it_came_from_an_api(token):
    send(token, event_from_tap({"user": {"phone": PHONE}, "items": [{"mobile": PHONE}]}))
    rows = {(r["field"], r["category"], r["source_kind"]) for r in flows.rows(get_store(), ORG)}
    assert rows == {("user.phone", "phone", "api"), ("items[].mobile", "phone", "api")}


def test_a_declared_field_is_judged_by_its_leaf_name(token, monkeypatch):
    # the real retail_co policy declares phone for some systems; the path user.phone must resolve to that declaration
    from org_config.schema import OrgConfig
    cfg = OrgConfig.model_validate({"org_id": ORG, "fields": [
        {"field_name": "phone", "pii_category": "phone", "declared_purpose": "order_updates", "consent_scope": "service_delivery",
         "retention_days": 365, "source_system": "customer-api"}]})
    import registry.loader as loader
    monkeypatch.setattr(loader, "load_org_config", lambda org: cfg)
    r = send(token, event_from_tap({"user": {"phone": PHONE}}))
    assert r.status_code == 200 and r.json()["verdicts"] == []          # declared, in a system that may hold it: quiet


def test_one_incident_for_the_same_route_and_field_however_often_it_occurs(token):
    for _ in range(5):
        send(token, event_from_tap({"user": {"aadhaar_no": AADHAAR}}))
    rows, total = get_store().list_incidents(ORG)
    assert total == 1 and rows[0]["count"] == 5


def test_a_hashed_identifier_in_a_payload_reaches_the_lookup_index(token):
    key = get_store().keyring.current(ORG, "agent")[1]
    tap = vt.Tap("http://127.0.0.1:1", "t", ORG, "customer-api", mode="hash", hash_key=key, start=False)
    tap.observe("GET", "/c/1", 200, "response", json.dumps({"user": {"phone": "+91 " + PHONE}}).encode())
    r = send(token, tap.q.get_nowait())
    assert r.status_code == 200
    found = get_store().subjects.lookup_tokens(ORG, "phone", get_store().subjects.tokens_for_identifier(ORG, "phone", PHONE))
    assert [(s["system"], s["events"]) for s in found["systems"]] == [("customer-api", 1)]


def test_a_forged_claim_without_placeholders_is_no_finding(token):
    event = event_from_tap({"user": {"phone": PHONE}})
    event["fields"] = {"user.phone": "not a placeholder"}
    r = send(token, event)
    assert r.status_code == 200 and r.json()["verdicts"] == []
