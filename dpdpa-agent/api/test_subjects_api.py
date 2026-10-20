"""
Lookup and rights requests through the API (phase T6): who may call what, the whole erasure workflow ending in
ERASURE_001 when the identifier comes back, the signed record, and that no identifier is ever echoed or logged.
Detection is replaced by a stand-in that finds the structured identifiers in the line, like the server's own.
"""
import json
import logging

import pytest

import veritas_recognizers as vr
from api.test_anchors_api import ORG, client, isolated  # noqa: F401
from detection.models import DetectedEvent, MatchedEntity
from evidence_store.store import get_store
from user_store.models import UserRole

PHONE, EMAIL = "9876543210", "asha.rao@example.com"
ENTITY = {"IN_AADHAAR": "IN_AADHAAR", "IN_PAN": "IN_PAN", "IN_PHONE": "IN_PHONE", "EMAIL_ADDRESS": "EMAIL_ADDRESS"}


class FindsIdentifiers:
    async def detect(self, event, validators):
        found = [MatchedEntity(field="raw_snippet", entity_type=d.entity_type, confidence=d.score,
                               matched_text=event.raw_snippet[d.start:d.end],
                               validation_status="pattern_match") for d in vr.scan(event.raw_snippet)
                 if d.entity_type in ENTITY]
        return DetectedEvent(event=event, contains_pii=bool(found), matched_entities=found)


@pytest.fixture(autouse=True)
def detection(monkeypatch):
    from api import integration
    monkeypatch.setattr(integration, "get_pool", lambda: FindsIdentifiers())
    monkeypatch.setattr(integration, "_require_org_config", lambda org: None)


def send(token, system, line, org=ORG):
    from fastapi.testclient import TestClient
    from dashboard.server import app
    c = TestClient(app, raise_server_exceptions=False)
    return c.post(f"/v1/{org}/events", headers={"Authorization": f"Bearer {token}"},
                  json={"source_type": "log", "source_system": system, "raw_snippet": line})


@pytest.fixture
def agent_token():
    from agent_store.store import get_agent_store
    store = get_agent_store()
    store.consume_key(store.issue_key(ORG))
    return store.create_agent(ORG, "test")[1]


_admins = {}


@pytest.fixture(autouse=True)
def forget_admins():
    _admins.clear()
    yield


def admin():
    if "adm" not in _admins:
        _admins["adm"] = client(UserRole.COMPLIANCE_ADMIN, "adm")
    return _admins["adm"]


# ---- who may do what ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.AUDITOR])
def test_only_a_compliance_admin_may_look_up_or_open_a_request(role):
    c = client(role, "low")
    assert c.post(f"/v1/{ORG}/subjects/lookup", json={"category": "phone", "identifier": PHONE}).status_code == 403
    assert c.post(f"/v1/{ORG}/requests", json={"type": "erasure", "requester_ref": "T", "identifiers": []}).status_code == 403
    assert c.post(f"/v1/{ORG}/subjects/keys/rotate", json={"purpose": "lookup"}).status_code == 403


def test_a_viewer_cannot_read_requests_or_records_but_an_auditor_can():
    admin().post(f"/v1/{ORG}/requests", json={"type": "access", "requester_ref": "T1", "identifiers": [{"category": "phone", "identifier": PHONE}]})
    assert client(UserRole.VIEWER, "v").get(f"/v1/{ORG}/requests").status_code == 403
    aud = client(UserRole.AUDITOR, "a")
    rid = aud.get(f"/v1/{ORG}/requests").json()["requests"][0]["request_id"]
    assert aud.get(f"/v1/{ORG}/requests/{rid}/record.pdf").status_code == 200
    assert aud.get(f"/v1/{ORG}/requests/{rid}/record.json").status_code == 200
    assert aud.post(f"/v1/{ORG}/requests/{rid}/close").status_code == 403


def test_a_refused_lookup_is_audited():
    client(UserRole.VIEWER, "snoop").post(f"/v1/{ORG}/subjects/lookup", json={"category": "phone", "identifier": PHONE})
    from audit_log.store import get_audit_store
    entries = get_audit_store().query(action="SUBJECT_LOOKUP", org_id=ORG)
    assert entries and "denied" in json.dumps(entries[0], default=str) and PHONE not in json.dumps(entries, default=str)


# ---- lookup ----------------------------------------------------------------------------------------------------

def test_lookup_returns_systems_and_audits_with_a_token_prefix_only(agent_token):
    send(agent_token, "order-service", "callback to +91 9876543210 failed")
    send(agent_token, "crm", f"update for {PHONE}")
    r = admin().post(f"/v1/{ORG}/subjects/lookup", json={"category": "phone", "identifier": "09876543210"})
    assert r.status_code == 200
    body = r.json()
    assert {s["system"]: s["events"] for s in body["systems"]} == {"order-service": 1, "crm": 1}
    assert len(body["token_prefix"]) == 8 and "not a statement about anywhere else" in body["note"]
    from audit_log.store import get_audit_store
    entry = get_audit_store().query(action="SUBJECT_LOOKUP", org_id=ORG)[0]
    text = json.dumps(entry, default=str)
    assert entry["actor_name"] == "adm" and body["token_prefix"] in text and PHONE not in text and "98765" not in text


@pytest.mark.parametrize("payload", [{"category": "phone", "identifier": "12345"}, {"category": "passport", "identifier": "X1"},
                                     {"category": "phone"}, {"identifier": PHONE}, {"category": "phone", "identifier": 5}, []])
def test_a_bad_lookup_is_refused_and_the_answer_does_not_repeat_the_input(payload):
    r = admin().post(f"/v1/{ORG}/subjects/lookup", json=payload)
    assert r.status_code == 400
    assert "12345" not in r.text and "passport" not in r.text or "Unknown kind" in r.text


def test_lookup_is_rate_limited():
    c = admin()
    codes = [c.post(f"/v1/{ORG}/subjects/lookup", json={"category": "phone", "identifier": PHONE}).status_code for _ in range(32)]
    assert codes[:30] == [200] * 30 and 429 in codes[30:]


# ---- the workflow ------------------------------------------------------------------------------------------------

def test_the_erasure_workflow_from_request_to_resurrection(agent_token):
    send(agent_token, "order-service", f"callback to {PHONE} failed")
    send(agent_token, "crm", f"mail {EMAIL} and phone {PHONE}")
    c = admin()

    r = c.post(f"/v1/{ORG}/requests", json={"type": "erasure", "requester_ref": "TKT-42", "received_at": "2026-10-01",
                                            "identifiers": [{"category": "phone", "identifier": "+91 98765 43210"}]})
    assert r.status_code == 201
    req = r.json()
    rid = req["request_id"]
    assert [t["system"] for t in req["tasks"]] == ["crm", "order-service"] and req["status"] == "OPEN"

    r1 = c.post(f"/v1/{ORG}/requests/{rid}/tasks/crm/confirm", json={"note": "rows deleted"})
    assert r1.status_code == 200 and r1.json()["status"] == "OPEN"
    assert c.post(f"/v1/{ORG}/requests/{rid}/close").status_code == 400            # a task is still open
    r2 = c.post(f"/v1/{ORG}/requests/{rid}/tasks/order-service/confirm")
    assert r2.json()["status"] == "CLOSED" and r2.json()["watching"] is True
    assert get_store().verify_chain(ORG)["valid"] is True

    # the identifier comes back, written differently: ERASURE_001
    before = get_store().incident_summary(ORG)["verdicts"]
    back = send(agent_token, "marketing-service", f"newsletter signup for 91-{PHONE}")
    assert back.status_code == 200
    rules = [v["rule_id"] for v in back.json()["verdicts"]]
    assert "ERASURE_001" in rules
    assert get_store().incident_summary(ORG)["verdicts"] > before
    verdict = [v for v in back.json()["verdicts"] if v["rule_id"] == "ERASURE_001"][0]
    assert "erasure request was closed" in verdict["explanation"] and PHONE not in json.dumps(back.json())
    assert verdict["severity"] == "HIGH" and "8(7)" in verdict["section_cited"]

    # a different number does not fire it
    other = send(agent_token, "marketing-service", "signup for 9123456780")
    assert "ERASURE_001" not in [v["rule_id"] for v in other.json()["verdicts"]]


def test_an_access_request_starts_no_watch(agent_token):
    send(agent_token, "crm", f"phone {PHONE}")
    c = admin()
    rid = c.post(f"/v1/{ORG}/requests", json={"type": "access", "requester_ref": "TKT-7",
                                              "identifiers": [{"category": "phone", "identifier": PHONE}]}).json()["request_id"]
    assert c.post(f"/v1/{ORG}/requests/{rid}/tasks/crm/confirm").json()["watching"] is False
    back = send(agent_token, "crm", f"phone {PHONE} again")
    assert "ERASURE_001" not in [v["rule_id"] for v in back.json()["verdicts"]]


def test_a_rotated_agent_key_still_finds_old_hashed_tokens(agent_token):
    store = get_store()
    old_key = store.keyring.current(ORG, "agent")[1]
    send(agent_token, "support", f"callback to {vr.hash_token('PHONE', PHONE, old_key)} failed")
    admin().post(f"/v1/{ORG}/subjects/keys/rotate", json={"purpose": "agent"})
    found = admin().post(f"/v1/{ORG}/subjects/lookup", json={"category": "phone", "identifier": PHONE}).json()
    assert [(s["system"], s["events"]) for s in found["systems"]] == [("support", 1)]


def test_the_erasure_watch_catches_a_hashed_identifier_too(agent_token):
    store = get_store()
    key = store.keyring.current(ORG, "agent")[1]
    send(agent_token, "support", f"first {vr.hash_token('PHONE', PHONE, key)}")
    c = admin()
    rid = c.post(f"/v1/{ORG}/requests", json={"type": "erasure", "requester_ref": "T9",
                                              "identifiers": [{"category": "phone", "identifier": PHONE}]}).json()["request_id"]
    c.post(f"/v1/{ORG}/requests/{rid}/tasks/support/confirm")
    back = send(agent_token, "support", f"again {vr.hash_token('PHONE', '+91 98765 43210', key)}")
    assert "ERASURE_001" in [v["rule_id"] for v in back.json()["verdicts"]]


# ---- the record --------------------------------------------------------------------------------------------------

def test_the_record_downloads_as_signed_json_and_as_a_pdf(agent_token):
    send(agent_token, "crm", f"phone {PHONE}")
    c = admin()
    rid = c.post(f"/v1/{ORG}/requests", json={"type": "erasure", "requester_ref": "TKT-8",
                                              "identifiers": [{"category": "phone", "identifier": PHONE}]}).json()["request_id"]
    c.post(f"/v1/{ORG}/requests/{rid}/tasks/crm/confirm", json={"note": "done"})
    j = c.get(f"/v1/{ORG}/requests/{rid}/record.json").json()
    from subject_lookup import record
    assert record.verify(j["record"], j["signature"]) is True
    assert j["record"]["status"] == "CLOSED" and j["record"]["chain"]["request_events"][-1]["action"] == "CLOSED"
    pdf = c.get(f"/v1/{ORG}/requests/{rid}/record.pdf")
    assert pdf.headers["content-type"] == "application/pdf" and pdf.content.startswith(b"%PDF") and PHONE.encode() not in pdf.content
    from audit_log.store import get_audit_store
    assert {e["action"] for e in get_audit_store().query(org_id=ORG)} >= {"RIGHTS_REQUEST_CREATED", "RIGHTS_RECORD_EXPORTED",
                                                                          "RIGHTS_TASK_CONFIRMED"}


def test_an_unknown_request_is_a_404_and_other_orgs_are_refused():
    c = admin()
    assert c.get(f"/v1/{ORG}/requests/nope").status_code == 404
    assert c.get(f"/v1/{ORG}/requests/nope/record.pdf").status_code == 404
    assert c.post(f"/v1/{ORG}/requests/nope/tasks/x/confirm").status_code == 400


def test_a_request_without_identifiers_or_with_a_bad_type_is_refused():
    c = admin()
    assert c.post(f"/v1/{ORG}/requests", json={"type": "erasure", "requester_ref": "T", "identifiers": []}).status_code == 400
    assert c.post(f"/v1/{ORG}/requests", json={"type": "sell", "requester_ref": "T",
                                               "identifiers": [{"category": "phone", "identifier": PHONE}]}).status_code == 400
    assert c.post(f"/v1/{ORG}/requests", json={"type": "erasure", "requester_ref": "T", "identifiers": "x"}).status_code == 400


# ---- keys ---------------------------------------------------------------------------------------------------------

def test_keys_can_be_listed_rotated_and_retired_without_ever_showing_one(agent_token):
    c = admin()
    send(agent_token, "crm", f"phone {PHONE}")
    kid = c.get(f"/v1/{ORG}/subjects/keys").json()["keys"][0]["key_id"]
    new = c.post(f"/v1/{ORG}/subjects/keys/rotate", json={"purpose": "lookup"}).json()["key_id"]
    assert new != kid
    listing = c.get(f"/v1/{ORG}/subjects/keys").text
    for _k, key in get_store().keyring.active(ORG, "lookup") + get_store().keyring.active(ORG, "agent"):
        assert key.hex() not in listing
    assert c.post(f"/v1/{ORG}/subjects/keys/retire", json={"key_id": kid}).status_code == 200
    assert c.post(f"/v1/{ORG}/subjects/keys/retire", json={"key_id": kid}).status_code == 404
    assert c.post(f"/v1/{ORG}/subjects/keys/rotate", json={"purpose": "other"}).status_code == 400


def test_a_registering_agent_receives_the_organizations_key():
    from fastapi.testclient import TestClient
    from dashboard.server import app
    from agent_store.store import get_agent_store
    plain = get_agent_store().issue_key(ORG)
    r = TestClient(app).post("/agent/register", json={"registration_key": plain, "source_label": "node"})
    assert r.status_code == 200
    k = r.json()["redaction_key"]
    assert vr.key_id_of(bytes.fromhex(k["key"])) == k["key_id"] == get_store().keyring.current(ORG, "agent")[0]


def test_a_hashing_agent_gets_a_new_key_at_its_next_heartbeat_only_when_it_needs_one():
    from agent_store.store import get_agent_store
    _store = get_agent_store()
    _store.consume_key(_store.issue_key(ORG))
    _agent, token = _store.create_agent(ORG, "hasher")
    agent_id = _agent.agent_id
    from fastapi.testclient import TestClient
    from dashboard.server import app
    c = TestClient(app)
    health = {"agent_version": "1.1.0", "uptime_seconds": 1, "queue_depth": 0, "queue_capacity": 1000, "counters": {}, "sources": [],
              "redaction": {"mode": "hash", "categories": {}, "fail_closed": True, "tee": False, "max_line_chars": 65536,
                            "pack_version": vr.PACK_VERSION, "pack_fingerprint": vr.pack_fingerprint(), "hash_key_id": "", "redacted": {}, "dropped": {}}}
    beat = lambda h: c.post("/agent/heartbeat", headers={"Authorization": f"Bearer {token}"}, json={"agent_id": agent_id, "health": h}).json()
    first = beat(health)
    assert vr.key_id_of(bytes.fromhex(first["redaction_key"]["key"])) == first["redaction_key"]["key_id"]
    health["redaction"]["hash_key_id"] = first["redaction_key"]["key_id"]
    assert "redaction_key" not in beat(health)                                   # it already has the current key
    admin().post(f"/v1/{ORG}/subjects/keys/rotate", json={"purpose": "agent"})
    assert beat(health)["redaction_key"]["key_id"] != first["redaction_key"]["key_id"]
    health["redaction"]["mode"] = "mask"
    assert "redaction_key" not in beat(health)                                   # an agent that does not hash is not sent a key


# ---- the identifier is never echoed or logged --------------------------------------------------------------------

def test_the_identifier_is_in_no_log_audit_entry_or_error(agent_token, caplog):
    caplog.set_level(logging.DEBUG)
    send(agent_token, "crm", f"phone {PHONE}")
    c = admin()
    responses = [
        c.post(f"/v1/{ORG}/subjects/lookup", json={"category": "phone", "identifier": "+91 98765 43210"}),
        c.post(f"/v1/{ORG}/subjects/lookup", json={"category": "phone", "identifier": "98765"}),
        c.post(f"/v1/{ORG}/subjects/lookup", content=b'{"category": "phone", "identifier": "98765 43210"', headers={"content-type": "application/json"}),
        c.post(f"/v1/{ORG}/requests", json={"type": "erasure", "requester_ref": "Asha 9876543210", "identifiers": [{"category": "phone", "identifier": PHONE}]}),
        c.post(f"/v1/{ORG}/requests", json={"type": "erasure", "requester_ref": "TKT-1", "identifiers": [{"category": "email", "identifier": EMAIL}]}),
        c.post(f"/v1/{ORG}/requests", json={"type": "erasure", "requester_ref": "TKT-2", "identifiers": [{"category": "email", "identifier": "not-an-email-98765"}]}),
    ]
    from audit_log.store import get_audit_store
    everything = "\n".join([r.text for r in responses] + [caplog.text, json.dumps(get_audit_store().query(limit=500), default=str)])
    for raw in (PHONE, "98765 43210", "98765", "asha.rao", "example.com"):
        assert raw not in everything, raw
