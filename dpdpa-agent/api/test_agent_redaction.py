"""
Event schema 2 and the agent redaction report (phase T5), on the server: findings from placeholders and keyed tokens,
what is refused, what is reported to the dashboard. Detection is replaced by a stand-in that finds nothing, which is
exactly what the server sees in a line the agent has already masked.
"""
import pytest

import veritas_recognizers as vr
from api.test_agents import _register_agent, client, isolated_stores  # noqa: F401
from detection.agent_reported import matches_from_agent
from detection.models import DetectedEvent
from evidence_store.store import get_store
from incidents.template import template_of

ORG = "retail_co"
KEY = b"k" * 32


class NoDetection:
    """What the server's detector finds in text that holds only placeholders: nothing."""
    async def detect(self, event, validators):
        return DetectedEvent(event=event, contains_pii=False, matched_entities=[])


@pytest.fixture
def no_detection(monkeypatch):
    from api import integration
    monkeypatch.setattr(integration, "get_pool", lambda: NoDetection())


def post(token, line, **extra):
    return client.post(f"/v1/{ORG}/events", headers={"Authorization": f"Bearer {token}"},
                       json={"source_type": "log", "source_system": "support-ticketing", "raw_snippet": line, **extra})


# ---- the findings an agent reports ---------------------------------------------------------------------

def test_placeholders_become_findings_only_for_the_kinds_the_agent_names():
    line = "paid by [CARD_REDACTED] phone [PHONE_REDACTED] and [PHONE_REDACTED] mail [EMAIL_REDACTED]"
    got = matches_from_agent(line, {"card": 1, "phone": 2})
    assert sorted(m.entity_type for m in got) == ["CREDIT_CARD", "IN_PHONE"]    # one per kind: every placeholder reads alike
    assert all(m.field == "raw_snippet" for m in got)


def test_each_distinct_hashed_identifier_is_its_own_finding():
    a, b = vr.hash_token("PHONE", "9876543210", KEY), vr.hash_token("PHONE", "9123456780", KEY)
    got = matches_from_agent(f"{a} called {b} and {a}", {"phone": 3})
    assert sorted(m.matched_text for m in got) == sorted([a, b])


def test_a_claim_without_the_placeholder_in_the_text_is_no_finding():
    assert matches_from_agent("nothing masked here", {"phone": 5}) == []


def test_text_that_looks_like_a_placeholder_for_an_unnamed_kind_is_ignored():
    assert matches_from_agent("[PHONE_REDACTED]", {}) == [] and matches_from_agent("[PHONE_REDACTED]", {"phone": 0}) == []


# ---- through ingest --------------------------------------------------------------------------------------

def test_a_masked_line_still_produces_a_finding_and_a_count(no_detection):
    _, token = _register_agent(ORG)
    r = post(token, "agent note: card [CARD_REDACTED] read aloud", schema=2, redaction_mode="mask",
             recognizer_pack_version=vr.PACK_VERSION, agent_detections={"card": 1})
    assert r.status_code == 200 and r.json()["contains_pii"] is True
    assert len(r.json()["verdicts"]) == 1
    rows = get_store().get_by_verdict_id  # noqa: F841
    assert get_store().incident_summary(ORG)["incidents"] == 1
    from evidence_store import flows
    assert {x["category"] for x in flows.rows(get_store(), ORG)} == {"card"}


def test_the_incident_of_a_masked_line_reads_like_the_masked_line(no_detection):
    _, token = _register_agent(ORG)
    for n in range(4):
        post(token, f"ticket {n}: aadhaar [AADHAAR_REDACTED] shared", schema=2, redaction_mode="mask",
             agent_detections={"aadhaar": 1})
    rows, total = get_store().list_incidents(ORG)
    assert total == 1 and rows[0]["count"] == 4 and "<PII:AADHAAR>" in rows[0]["template"]


def test_a_hashed_identifier_is_one_incident_template_but_distinct_findings(no_detection):
    _, token = _register_agent(ORG)
    for number in ("9876543210", "9123456780", "9988776655"):
        post(token, f"callback to {vr.hash_token('PHONE', number, KEY)} failed", schema=2, redaction_mode="hash",
             agent_detections={"phone": 1})
    assert get_store().incident_summary(ORG)["incidents"] == 1
    assert get_store().incident_summary(ORG)["verdicts"] == 3
    assert template_of("callback to [PHONE#a1b2c3.0123456789abcdef] failed").text == template_of("callback to [PHONE_REDACTED] failed").text


def test_schema_1_events_are_unchanged(no_detection):
    _, token = _register_agent(ORG)
    r = post(token, "agent note: card [CARD_REDACTED] read aloud")       # no schema fields: a placeholder alone is no claim
    assert r.status_code == 200 and r.json()["contains_pii"] is False and r.json()["verdicts"] == []


@pytest.mark.parametrize("extra", [
    {"agent_detections": {"passport": 1}},
    {"agent_detections": {"phone": -1}},
    {"agent_detections": {"phone": 10 ** 9}},
    {"agent_detections": {"phone": True}},
    {"redaction_mode": "scramble"},
    {"recognizer_pack_version": "1.0 <script>"},
    {"schema": 3},
])
def test_malformed_schema_2_fields_are_refused(no_detection, extra):
    _, token = _register_agent(ORG)
    assert post(token, "x [PHONE_REDACTED]", **extra).status_code == 422


# ---- what the dashboard is told --------------------------------------------------------------------------

def health(**redaction):
    return {"agent_version": "1.1.0", "uptime_seconds": 5, "queue_depth": 0, "queue_capacity": 1000, "counters": {},
            "sources": [], "redaction": {"mode": "mask", "categories": {"phone": "mask", "card": "drop"},
                                         "fail_closed": True, "tee": True, "max_line_chars": 65536,
                                         "pack_version": vr.PACK_VERSION, "pack_fingerprint": vr.pack_fingerprint(),
                                         "redacted": {"phone": 3}, "dropped": {"card": 1}, **redaction}}


def beat(agent_id, token, h):
    return client.post("/agent/heartbeat", headers={"Authorization": f"Bearer {token}"},
                       json={"agent_id": agent_id, "health": h})


def test_the_heartbeat_stores_the_redaction_report_and_answers_with_the_server_rules():
    agent_id, token = _register_agent(ORG)
    r = beat(agent_id, token, health())
    assert r.status_code == 200 and r.json()["recognizer_pack_fingerprint"] == vr.pack_fingerprint()
    a = client.get(f"/agents/{agent_id}").json()
    assert a["health"]["redaction"]["mode"] == "mask" and a["health"]["redaction"]["dropped"] == {"card": 1}
    assert a["redaction_pack_mismatch"] is False


def test_different_rules_are_flagged():
    agent_id, token = _register_agent(ORG)
    beat(agent_id, token, health(pack_fingerprint="0123456789abcdef"))
    assert client.get(f"/agents/{agent_id}").json()["redaction_pack_mismatch"] is True


def test_an_agent_without_the_report_is_not_flagged():
    agent_id, token = _register_agent(ORG)
    h = health()
    del h["redaction"]
    beat(agent_id, token, h)
    assert client.get(f"/agents/{agent_id}").json()["redaction_pack_mismatch"] is False


@pytest.mark.parametrize("bad", [
    {"mode": "scramble"}, {"categories": {"phone": "shred"}}, {"categories": {f"k{i}": "mask" for i in range(11)}},
    {"pack_version": "x" * 33}, {"redacted": {"x" * 21: 1}},
])
def test_a_malformed_redaction_report_is_refused(bad):
    agent_id, token = _register_agent(ORG)
    assert beat(agent_id, token, health(**bad)).status_code == 422
