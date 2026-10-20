"""OpenTelemetry logs (phase F): an OTLP/HTTP JSON export becomes events like any agent's lines."""
import json

import pytest

import veritas_recognizers as vr
from api.test_agents import _register_agent, client as admin_client, isolated_stores  # noqa: F401
from detection.models import DetectedEvent, MatchedEntity
from evidence_store import flows
from evidence_store.store import get_store

ORG = "retail_co"
PHONE = "9876543210"


class Finds:
    async def detect(self, event, validators):
        found = [MatchedEntity(field="raw_snippet", entity_type=d.entity_type, confidence=d.score, matched_text=event.raw_snippet[d.start:d.end],
                               validation_status="pattern_match") for d in vr.scan(event.raw_snippet)]
        for name, value in event.fields.items():                      # like the real detector, structured fields are scanned too
            found += [MatchedEntity(field=name, entity_type=d.entity_type, confidence=d.score, matched_text=value[d.start:d.end],
                                    validation_status="pattern_match") for d in vr.scan(value)]
        return DetectedEvent(event=event, contains_pii=bool(found), matched_entities=found)


@pytest.fixture
def token(monkeypatch):
    from api import integration
    monkeypatch.setattr(integration, "get_pool", lambda: Finds())
    return _register_agent(ORG)[1]


def attr(k, v):
    return {"key": k, "value": {"stringValue": v}}


def export(*records, service="checkout"):
    return {"resourceLogs": [{"resource": {"attributes": [attr("service.name", service)]},
                              "scopeLogs": [{"scope": {"name": "app"}, "logRecords": list(records)}]}]}


def rec(body, **extra):
    return {"timeUnixNano": "1760000000000000000", "severityText": "INFO", "body": {"stringValue": body}, **extra}


def post(token, doc, ctype="application/json", raw=None):
    from fastapi.testclient import TestClient
    from dashboard.server import app
    return TestClient(app, raise_server_exceptions=False).post(
        f"/v1/{ORG}/otlp/logs", headers={"Authorization": f"Bearer {token}", "Content-Type": ctype},
        content=raw if raw is not None else json.dumps(doc))


def test_a_record_with_personal_data_is_judged_like_a_log_line(token):
    r = post(token, export(rec(f"callback to {PHONE} failed"), rec("healthy")))
    assert r.status_code == 200 and r.json() == {}
    rows, total = get_store().list_incidents(ORG)
    assert total == 1 and rows[0]["source_system"] == "checkout"
    assert [(x["source_system"], x["category"], x["source_kind"]) for x in flows.rows(get_store(), ORG)] == [("checkout", "phone", "otlp")]
    assert get_store().verify_chain(ORG)["valid"] is True


def test_attributes_become_fields_and_the_service_name_the_system(token):
    post(token, export(rec("order paid", attributes=[attr("user.phone", PHONE), attr("order.id", "7")]), service="orders"))
    assert {(x["source_system"], x["field"]) for x in flows.rows(get_store(), ORG)} == {("orders", "user.phone")}


def test_a_record_without_a_body_uses_its_attributes_and_an_empty_one_is_rejected(token):
    ok = post(token, export({"attributes": [attr("note", f"call {PHONE}")]}))
    assert ok.status_code == 200 and ok.json() == {} and flows.rows(get_store(), ORG)
    empty = post(token, export({"severityText": "INFO"}, rec("kept")))
    assert empty.json()["partialSuccess"]["rejectedLogRecords"] == 1


def test_non_string_values_and_several_resources_are_handled(token):
    doc = {"resourceLogs": [
        {"resource": {"attributes": [attr("service.name", "a")]}, "scopeLogs": [{"logRecords": [{"body": {"intValue": "42"}}]}]},
        {"resource": {"attributes": []}, "scopeLogs": [{"logRecords": [rec(f"call {PHONE}")]}]}]}
    assert post(token, doc).status_code == 200
    assert {x["source_system"] for x in flows.rows(get_store(), ORG)} == {"otlp"}          # no service.name: named "otlp"


@pytest.mark.parametrize("ctype", ["application/x-protobuf", "text/plain", "application/json; charset=utf-8"])
def test_only_json_is_accepted(token, ctype):
    r = post(token, export(rec("x")), ctype=ctype)
    assert (r.status_code == 200) == ctype.startswith("application/json")
    if r.status_code != 200:
        assert r.status_code == 415 and "JSON" in r.json()["detail"]


@pytest.mark.parametrize("raw", ["not json", "[]", '{"resourceLogs": "x"}', ""])
def test_malformed_bodies_are_400(token, raw):
    assert post(token, None, raw=raw).status_code == 400


def test_limits(token):
    assert post(token, export(*[rec("x")] * 501)).status_code == 413
    assert post(token, export(rec("x" * 1_100_000))).status_code == 413


def test_a_token_is_required_and_belongs_to_the_organization():
    from fastapi.testclient import TestClient
    from dashboard.server import app
    c = TestClient(app, raise_server_exceptions=False)
    assert c.post(f"/v1/{ORG}/otlp/logs", json=export(rec("x"))).status_code == 401
    assert c.post(f"/v1/{ORG}/otlp/logs", json=export(rec("x")), headers={"Authorization": "Bearer nope"}).status_code == 401


def test_a_hostile_service_name_or_field_name_is_rejected_not_stored(token):
    r = post(token, export(rec("x"), service="<script>alert(1)</script>"))
    assert r.status_code == 200 and r.json()["partialSuccess"]["rejectedLogRecords"] == 1
    assert get_store().incident_summary(ORG)["verdicts"] == 0
