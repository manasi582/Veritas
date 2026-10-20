"""Notice coverage through the API (phase E): the review is readable, and a kind of data no notice covers is a finding, once."""
import json

import pytest

import veritas_recognizers as vr
from api.test_agents import _register_agent, client as admin_client, isolated_stores  # noqa: F401
from detection.models import DetectedEvent, MatchedEntity
from evidence_store.store import get_store
from notice_registry.test_notice_registry import notice, policy

ORG = "retail_co"
PHONE = "9876543210"


class Finds:
    async def detect(self, event, validators):
        found = [MatchedEntity(field="raw_snippet", entity_type=d.entity_type, confidence=d.score, matched_text=event.raw_snippet[d.start:d.end],
                               validation_status="pattern_match") for d in vr.scan(event.raw_snippet)]
        return DetectedEvent(event=event, contains_pii=bool(found), matched_entities=found)


@pytest.fixture
def setup(monkeypatch):
    from api import integration, notices
    cfg = policy([notice("n1", cats=("phone",), systems=("support-ticketing",))])
    cfg = cfg.model_copy(update={"org_id": ORG})
    monkeypatch.setattr(notices, "load_org_config", lambda org: cfg)
    real = integration.load_org_config
    monkeypatch.setattr(integration, "load_org_config", lambda org: cfg if org == ORG else real(org))
    monkeypatch.setattr(integration, "get_pool", lambda: Finds())
    return _register_agent(ORG)[1]


def send(token, line, system="support-ticketing"):
    from fastapi.testclient import TestClient
    from dashboard.server import app
    return TestClient(app, raise_server_exceptions=False).post(
        f"/v1/{ORG}/events", headers={"Authorization": f"Bearer {token}"},
        json={"source_type": "log", "source_system": system, "raw_snippet": line})


def test_the_review_is_readable_and_says_what_it_cannot_do(setup):
    body = admin_client.get(f"/v1/{ORG}/notices").json()
    assert body["enabled"] is True and body["notices"][0]["notice_id"] == "n1" and body["notices"][0]["status"] == "current"
    assert "cannot read a notice" in body["note"] and "legally adequate" in body["note"]


def test_a_covered_kind_of_data_raises_nothing_and_an_uncovered_one_raises_once(setup):
    covered = send(setup, f"call {PHONE}")
    assert "NOTICE_001" not in [v["rule_id"] for v in covered.json()["verdicts"]]
    first = send(setup, "mail asha.rao@example.com about it")
    notice_findings = [v for v in first.json()["verdicts"] if v["rule_id"] == "NOTICE_001"]
    assert len(notice_findings) == 1 and notice_findings[0]["field"] == "email"
    assert "no current notice" in notice_findings[0]["explanation"] and "legally adequate" in notice_findings[0]["explanation"]
    again = send(setup, "mail asha.rao@example.com again")
    assert "NOTICE_001" not in [v["rule_id"] for v in again.json()["verdicts"]]
    assert get_store().verify_chain(ORG)["valid"] is True


def test_the_data_map_page_data_shows_the_gap(setup):
    send(setup, "mail asha.rao@example.com")
    body = admin_client.get(f"/v1/{ORG}/notices").json()
    assert [(o["system"], o["category"], o["covered"]) for o in body["observed"] if o["category"] == "email"] == [("support-ticketing", "email", False)]
    assert body["summary"]["observed_uncovered"] == 1 and "asha.rao" not in json.dumps(body)


def test_without_notices_in_the_policy_nothing_is_raised(monkeypatch):
    from api import integration, notices
    cfg = policy().model_copy(update={"org_id": ORG})
    monkeypatch.setattr(notices, "load_org_config", lambda org: cfg)
    real = integration.load_org_config
    monkeypatch.setattr(integration, "load_org_config", lambda org: cfg if org == ORG else real(org))
    monkeypatch.setattr(integration, "get_pool", lambda: Finds())
    r = send(_register_agent(ORG)[1], "mail asha.rao@example.com")
    assert "NOTICE_001" not in [v["rule_id"] for v in r.json()["verdicts"]]
    assert admin_client.get(f"/v1/{ORG}/notices").json()["enabled"] is False


def test_an_unknown_organization_is_a_404():
    assert admin_client.get("/v1/no_such_org/notices").status_code in (403, 404)
