"""
Identifier lookup and rights requests (phase T6), at the store level: normalising, keys and rotation, the index, the
database scan, requests and their chain events, the watch list, and the signed record.
"""
import json
import sqlite3

import pytest

import veritas_recognizers as vr
from detection.models import MatchedEntity
from evidence_store.store import EvidenceStore
from subject_lookup import record as subject_record
from subject_lookup import rights
from subject_lookup.index import InvalidIdentifier, clean_identifier

ORG = "subj_org"
PHONE = "9876543210"
EMAIL = "asha.rao@example.com"
AADHAAR = "2345 6789 0124"


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "data"))
    s = EvidenceStore(tmp_path / "e.db")
    yield s
    s.close()


def match(entity_type, text, validation="pattern_match"):
    return MatchedEntity(field="raw_snippet", entity_type=entity_type, confidence=0.9, matched_text=text,
                         validation_status=validation)


def see(store, system, *matches, org=ORG, line="", verdicts=()):
    tokens = store.subjects.tokens_for_event(org, matches, line)
    store.subjects.record(org, system, tokens, verdicts)
    return tokens


def lookup(store, category, identifier, org=ORG):
    return store.subjects.lookup_tokens(org, category, store.subjects.tokens_for_identifier(org, category, identifier))


# ---- normalising and tokens -----------------------------------------------------------------------------

@pytest.mark.parametrize("written", ["9876543210", "+91 98765 43210", "98765-43210", "09876543210", "91-9876543210", "+91-9876543210"])
def test_the_same_phone_written_many_ways_is_one_identifier(written):
    assert clean_identifier("phone", written) == "9876543210"


def test_other_kinds_normalise(store):
    assert clean_identifier("email", "  Asha.Rao@Example.COM ") == EMAIL
    assert clean_identifier("aadhaar", AADHAAR) == "234567890124"
    assert clean_identifier("pan", " abcpe1234f ") == "ABCPE1234F"
    assert clean_identifier("card", "4111-1111 1111-1111") == "4111111111111111"


@pytest.mark.parametrize("category,value", [("phone", "12345"), ("phone", "5876543210"), ("aadhaar", "1234"), ("pan", "ABC"),
                                            ("email", "nobody"), ("card", "12"), ("passport", "X1234567"), ("phone", None)])
def test_an_identifier_that_does_not_fit_is_refused_without_repeating_it(category, value):
    with pytest.raises(InvalidIdentifier) as e:
        clean_identifier(category, value)
    assert (str(value) not in str(e.value)) or value in (None, "")


def test_all_writings_of_a_phone_give_one_token_and_one_count(store):
    for written in ("9876543210", "+91 98765 43210", "09876543210"):
        see(store, "order-service", match("IN_PHONE", written))
    found = lookup(store, "phone", "91-9876543210")
    assert [(s["system"], s["events"]) for s in found["systems"]] == [("order-service", 3)]


# ---- keys ------------------------------------------------------------------------------------------------

def test_keys_are_made_once_and_stored_encrypted(store, tmp_path):
    kid, key = store.keyring.current(ORG, "lookup")
    assert store.keyring.current(ORG, "lookup") == (kid, key) and len(key) == 32 and kid == vr.key_id_of(key)
    store.close()
    raw = (tmp_path / "e.db").read_bytes()
    assert key.hex().encode() not in raw
    store.__init__(tmp_path / "e.db")


def test_the_lookup_key_and_the_agent_key_are_different(store):
    assert store.keyring.current(ORG, "lookup")[1] != store.keyring.current(ORG, "agent")[1]


def test_after_rotation_old_tokens_are_still_found(store):
    see(store, "order-service", match("IN_PHONE", PHONE))
    old = store.keyring.current(ORG, "lookup")[0]
    new = store.keyring.rotate(ORG, "lookup")
    store.subjects.forget_keys(ORG)
    assert new != old and store.keyring.current(ORG, "lookup")[0] == new
    see(store, "crm", match("IN_PHONE", PHONE))                         # new events use the new key
    found = lookup(store, "phone", PHONE)
    assert sorted((s["system"], s["events"]) for s in found["systems"]) == [("crm", 1), ("order-service", 1)]
    assert found["keys_tried"] == 2


def test_a_retired_key_no_longer_finds_its_tokens(store):
    see(store, "order-service", match("IN_PHONE", PHONE))
    old = store.keyring.current(ORG, "lookup")[0]
    store.keyring.rotate(ORG, "lookup")
    store.subjects.forget_keys(ORG)
    assert store.keyring.retire(ORG, old) is True
    assert lookup(store, "phone", PHONE)["systems"] == []


def test_key_listing_never_shows_key_material(store):
    store.keyring.current(ORG, "lookup")
    key = store.keyring.active(ORG, "lookup")[0][1]
    assert key.hex() not in json.dumps(store.keyring.listing(ORG))


# ---- the index -------------------------------------------------------------------------------------------

def test_counts_per_system_with_first_and_last_seen(store):
    see(store, "order-service", match("IN_PHONE", PHONE))
    see(store, "order-service", match("IN_PHONE", PHONE))
    see(store, "crm", match("EMAIL_ADDRESS", EMAIL), match("IN_PHONE", PHONE))
    phone = lookup(store, "phone", PHONE)
    assert {s["system"]: s["events"] for s in phone["systems"]} == {"order-service": 2, "crm": 1}
    assert all(s["first_seen"] <= s["last_seen"] for s in phone["systems"])
    assert {s["system"] for s in lookup(store, "email", EMAIL)["systems"]} == {"crm"}
    assert lookup(store, "email", "someone.else@example.com")["systems"] == []


def test_the_same_number_in_another_kind_is_a_different_identifier(store):
    see(store, "s", match("IN_PHONE", PHONE))
    assert lookup(store, "aadhaar", "234567890124")["systems"] == []


def test_other_organizations_have_their_own_keys_and_counts(store):
    see(store, "s", match("IN_PHONE", PHONE), org="org_a")
    assert lookup(store, "phone", PHONE, org="org_a")["systems"][0]["events"] == 1
    assert lookup(store, "phone", PHONE, org="org_b")["systems"] == []
    assert store.keyring.current("org_a", "lookup")[1] != store.keyring.current("org_b", "lookup")[1]


def test_a_failed_checksum_a_placeholder_and_a_name_are_not_indexed(store):
    assert see(store, "s", match("IN_AADHAAR", "1234 5678 9012", "failed_validation"),
               match("IN_PHONE", "[PHONE_REDACTED]"), match("PERSON", "Asha Rao")) == []


def test_a_hashed_identifier_from_an_agent_is_indexed_and_found(store):
    key = store.keyring.current(ORG, "agent")[1]
    token = vr.hash_token("PHONE", "+91 98765 43210", key)
    see(store, "support", line=f"callback to {token} failed")
    found = lookup(store, "phone", PHONE)
    assert [(s["system"], s["events"]) for s in found["systems"]] == [("support", 1)]


def test_a_token_made_under_an_unknown_key_is_kept_but_not_found(store):
    see(store, "support", line="callback to " + vr.hash_token("PHONE", PHONE, b"x" * 32))
    store.keyring.current(ORG, "agent")
    assert lookup(store, "phone", PHONE)["systems"] == []


def test_findings_are_linked_to_the_token(store):
    from evidence_store.test_evidence_store import _make_explained_verdict
    ev = _make_explained_verdict(tenant_id=ORG)
    store.append(ev)
    see(store, "s", match("IN_PHONE", PHONE), verdicts=[str(ev.verdict.verdict_id)])
    v = lookup(store, "phone", PHONE)["verdicts"]
    assert len(v) == 1 and v[0]["chain_hash"] and v[0]["violation_id"] == 1


def test_no_raw_identifier_is_in_the_database_file(store, tmp_path):
    see(store, "order-service", match("IN_PHONE", "+91 98765 43210"), match("EMAIL_ADDRESS", EMAIL),
        match("IN_AADHAAR", AADHAAR))
    lookup(store, "phone", PHONE)
    rights.create_request(store, ORG, "erasure", "TKT-1", [("phone", PHONE), ("email", EMAIL)], actor="asha")
    store.subjects.flush()
    store._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    store.close()
    blob = b"".join(p.read_bytes() for p in tmp_path.glob("e.db*"))
    for raw in (b"9876543210", b"98765 43210", b"asha.rao", b"example.com", b"234567890124", b"2345 6789", b"23456"):
        assert raw not in blob, raw
    # and a scan of every text column in the database
    con = sqlite3.connect(tmp_path / "e.db")
    for (table,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
        for row in con.execute(f'SELECT * FROM "{table}"'):
            assert "9876543210" not in repr(row) and "asha.rao" not in repr(row)
    con.close()
    store.__init__(tmp_path / "e.db")


# ---- rights requests -------------------------------------------------------------------------------------

def owners():
    return {"order-service": {"team": "Orders", "email": "orders@example.com"}}


def seeded(store):
    see(store, "order-service", match("IN_PHONE", PHONE))
    see(store, "crm", match("IN_PHONE", PHONE), match("EMAIL_ADDRESS", EMAIL))


def test_a_request_finds_the_systems_and_makes_one_task_each(store):
    seeded(store)
    r = rights.create_request(store, ORG, "erasure", "TKT-100", [("phone", PHONE)], owners=owners(), actor="asha")
    assert r["status"] == "OPEN" and r["type"] == "erasure" and r["requester_ref"] == "TKT-100"
    assert [(t["system"], t["owner"], t["status"]) for t in r["tasks"]] == [
        ("crm", "unassigned", "OPEN"), ("order-service", "Orders · orders@example.com", "OPEN")]
    assert [e["action"] for e in r["events"]] == ["CREATED", "TASKS_CREATED"]
    assert store.verify_chain(ORG)["valid"] is True


def test_the_request_closes_when_every_task_is_confirmed(store):
    seeded(store)
    r = rights.create_request(store, ORG, "erasure", "TKT-1", [("phone", PHONE)], owners=owners(), actor="asha")
    rid = r["request_id"]
    r = rights.confirm_task(store, ORG, rid, "crm", "ravi", "deleted rows")
    assert r["status"] == "OPEN"
    with pytest.raises(rights.RequestError):
        rights.close_request(store, ORG, rid, "asha")
    r = rights.confirm_task(store, ORG, rid, "order-service", "meera")
    assert r["status"] == "CLOSED" and r["closed_at"] and r["watching"] is True
    assert [e["action"] for e in r["events"]] == ["CREATED", "TASKS_CREATED", "TASK_CONFIRMED", "TASK_CONFIRMED", "CLOSED"]
    assert store.verify_chain(ORG)["valid"] is True
    for again in (lambda: rights.confirm_task(store, ORG, rid, "crm", "x"), lambda: rights.close_request(store, ORG, rid, "x")):
        with pytest.raises(rights.RequestError):
            again()


def test_a_request_that_found_nothing_is_closed_by_a_person(store):
    r = rights.create_request(store, ORG, "access", "TKT-2", [("phone", PHONE)], actor="asha")
    assert r["tasks"] == [] and r["status"] == "OPEN"
    assert rights.close_request(store, ORG, r["request_id"], "asha", "nothing observed")["status"] == "CLOSED"
    assert store.verify_chain(ORG)["valid"] is True


def test_only_a_closed_erasure_request_starts_a_watch(store):
    seeded(store)
    a = rights.create_request(store, ORG, "access", "TKT-3", [("phone", PHONE)], actor="a")
    for system in ("crm", "order-service"):
        a = rights.confirm_task(store, ORG, a["request_id"], system, "x")
    assert a["status"] == "CLOSED" and a["watching"] is False and store.subjects.watched(ORG) == {}


def test_the_status_cache_is_checked_by_the_chain(store):
    seeded(store)
    r = rights.create_request(store, ORG, "erasure", "TKT-4", [("phone", PHONE)], actor="a")
    store._conn.execute("UPDATE rights_requests SET status = 'CLOSED' WHERE request_id = ?", (r["request_id"],))
    store._conn.commit()
    assert store.verify_chain_detail(ORG)["reason"] == "STATUS_CACHE_MISMATCH"
    store._conn.execute("UPDATE rights_requests SET status = 'OPEN' WHERE request_id = ?", (r["request_id"],))
    store._conn.execute("UPDATE request_tasks SET status = 'CONFIRMED' WHERE request_id = ? AND system = 'crm'", (r["request_id"],))
    store._conn.commit()
    assert store.verify_chain_detail(ORG)["reason"] == "STATUS_CACHE_MISMATCH"


@pytest.mark.parametrize("ref", ["", "x" * 101, "Asha Rao 9876543210", "call 9876543210", "asha.rao@example.com", "naïve ünïcode"])
def test_the_requester_reference_must_be_opaque(store, ref):
    with pytest.raises(rights.RequestError):
        rights.create_request(store, ORG, "erasure", ref, [("phone", PHONE)], actor="a")


@pytest.mark.parametrize("kwargs", [{"req_type": "sell"}, {"identifiers": []}, {"identifiers": [("phone", "12")]},
                                    {"due_at": "next week"}])
def test_a_malformed_request_is_refused(store, kwargs):
    args = {"req_type": "erasure", "identifiers": [("phone", PHONE)], **kwargs}
    with pytest.raises(rights.RequestError):
        rights.create_request(store, ORG, args["req_type"], "TKT-5", args["identifiers"], actor="a", due_at=args.get("due_at"))


def test_there_is_no_deadline_unless_one_is_given_or_configured(store, monkeypatch):
    monkeypatch.delenv("VERITAS_RIGHTS_RESPONSE_DAYS", raising=False)
    assert rights.create_request(store, ORG, "access", "T1", [("phone", PHONE)], actor="a")["due_at"] is None
    r = rights.create_request(store, ORG, "access", "T2", [("phone", PHONE)], actor="a", due_at="2030-01-15")
    assert r["due_at"].startswith("2030-01-15") and r["overdue"] is False
    monkeypatch.setenv("VERITAS_RIGHTS_RESPONSE_DAYS", "30")
    r = rights.create_request(store, ORG, "access", "T3", [("phone", PHONE)], actor="a", received_at="2020-01-01")
    assert r["due_at"].startswith("2020-01-31") and r["overdue"] is True


def test_other_organizations_cannot_see_or_change_a_request(store):
    seeded(store)
    r = rights.create_request(store, ORG, "erasure", "T", [("phone", PHONE)], actor="a")
    with pytest.raises(rights.RequestError):
        rights.get_request(store, "other_org", r["request_id"])
    with pytest.raises(rights.RequestError):
        rights.confirm_task(store, "other_org", r["request_id"], "crm", "x")
    assert rights.list_requests(store, "other_org") == []


# ---- the signed record -----------------------------------------------------------------------------------

def closed_request(store):
    seeded(store)
    r = rights.create_request(store, ORG, "erasure", "TKT-9", [("phone", PHONE)], owners=owners(), actor="asha")
    for system in ("crm", "order-service"):
        r = rights.confirm_task(store, ORG, r["request_id"], system, "ravi", "done")
    return r


def test_the_record_is_signed_and_a_change_breaks_the_signature(store):
    r = closed_request(store)
    body = subject_record.build(store, ORG, r["request_id"])
    sig = subject_record.sign(body)
    assert sig["alg"] == "Ed25519" and subject_record.verify(body, sig) is True
    body["tasks"][0]["status"] = "OPEN"
    assert subject_record.verify(body, sig) is False


def test_the_record_references_chain_entries_and_says_what_it_is_not(store):
    r = closed_request(store)
    body = subject_record.build(store, ORG, r["request_id"])
    assert [e["action"] for e in body["chain"]["request_events"]] == ["CREATED", "TASKS_CREATED", "TASK_CONFIRMED", "TASK_CONFIRMED", "CLOSED"]
    assert all(len(e["chain_hash"]) == 64 for e in body["chain"]["request_events"]) and body["chain"]["head_hash"]
    text = " ".join(body["statements"])
    assert "not a certificate" in text and "erased everywhere" in text and "ERASURE_001" in text
    assert body["identifiers"][0]["systems"] and body["identifiers"][0]["token_prefix"]


def test_the_pdf_is_a_pdf_with_the_signature_and_without_the_identifier(store):
    r = closed_request(store)
    body = subject_record.build(store, ORG, r["request_id"])
    sig = subject_record.sign(body)
    pdf = subject_record.to_pdf(body, sig)
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    assert sig["signature"][:64].encode() in pdf and sig["signature"][64:].encode() in pdf
    assert b"certificate" in pdf and b"erased everywhere" in pdf and b"Lookup and erasure record" in pdf
    assert PHONE.encode() not in pdf and b"asha.rao" not in pdf
    assert subject_record.to_pdf(body, sig) == pdf                          # the same input gives the same bytes


def test_a_long_record_runs_onto_more_pages(store):
    from subject_lookup import pdf
    data = pdf.render("T", [("n", "line %d" % i) for i in range(200)])
    assert data.count(b"/Type /Page ") == 3 or data.count(b"/Type /Page ") >= 3


def test_the_exported_chain_holds_no_key_and_no_token(store):
    closed_request(store)
    exported = "".join(store.export_records(ORG) if not callable(getattr(store, "export_records", None)) else
                       (json.dumps(x) if not isinstance(x, str) else x for x in store.export_records(ORG)))
    for kid, key in store.keyring.active(ORG, "lookup") + store.keyring.active(ORG, "agent"):
        assert key.hex() not in exported
    assert "9876543210" not in exported
