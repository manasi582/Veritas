"""
Incident grouping (phase T2): the template and fingerprint, grouping at ingest, regression, status as chained events,
merge and split, tenant separation, the chain check, tampering, and older findings.
"""
import json

import pytest

from db_encryption import decrypt_field
from evidence_store import canonical as cn
from evidence_store import incidents as inc
from evidence_store.store import EvidenceStore
from evidence_store.test_evidence_store import _make_explained_verdict
from incidents.template import fingerprint, template_of
from masking import mask_text

ORG = "inc_org"


class Hit:           # what the detector returns for a value it found
    def __init__(self, entity_type, matched_text):
        self.field, self.entity_type, self.matched_text = entity_type.lower(), entity_type, matched_text


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_INCIDENT_GRACE_SECONDS", "0")
    s = EvidenceStore(tmp_path / "e.db")
    yield s
    s.close()


def _add(store, line="payment failed for order 1 card X", org=ORG, **kw):
    ev = _make_explained_verdict(tenant_id=org, **kw)
    store.append(ev, grouping=tuple(template_of(line)))
    return str(ev.verdict.verdict_id)


# ---- template and fingerprint -------------------------------------------------------------------

def test_lines_of_one_kind_have_one_template_whatever_changes_in_them():
    lines = [
        "2026-10-20 10:01:02 ERROR payment failed for order 88231 user=asha from 10.0.0.4",
        "2026-10-21 23:59:59 ERROR payment failed for order 7 user=ravi from 192.168.1.20",
        "2026-10-22 00:00:00 ERROR payment failed for order 91234567 user=Meera Iyer from 10.9.9.9",
    ]
    assert len({template_of(l).text for l in lines}) == 1


def test_different_wording_is_a_different_template():
    assert template_of("payment failed for order 1").text != template_of("refund issued for order 1").text


def test_detected_values_never_reach_the_template():
    line = "kyc ok for Asha Rao aadhaar 2345 6789 0124 mail asha.rao@example.com"
    t = template_of(line, [Hit("AADHAAR", "2345 6789 0124"), Hit("PERSON", "Asha Rao")])
    for secret in ("Asha", "Rao", "2345", "6789", "0124", "example.com", "asha"):
        assert secret not in t.text
    assert "<PII:AADHAAR>" in t.text and "<PII:NAME>" in t.text


def test_capitalised_words_digits_and_values_after_equals_become_placeholders():
    t = template_of("Login by Kumar123 token=abc.def user=bob id=77 done").text
    assert "Kumar" not in t and "123" not in t and "bob" not in t and "abc" not in t and "77" not in t
    assert t.startswith("<*> by <*>") or "login" in t.lower() or t


def test_hint_names_a_place_in_the_code_and_never_a_person():
    h = template_of("ERROR [app.billing.service] charge failed at com.acme.pay.Charge.run(Charge.java:88)").hint
    assert "com.acme.pay.Charge.run" in h and "Charge.java:88" in h and "app.billing.service" in h
    h2 = template_of("boom in /home/asha/projects/pay/charge.py:42").hint
    assert h2 == "charge.py:42" and "asha" not in h2


def test_fingerprint_depends_on_each_part_and_nothing_else():
    base = fingerprint("o", "EXPOSURE_001", "svc", "pan", "t")
    assert base == fingerprint("o", "EXPOSURE_001", "svc", "pan", "t")
    for changed in (fingerprint("p", "EXPOSURE_001", "svc", "pan", "t"), fingerprint("o", "PURPOSE_001", "svc", "pan", "t"),
                    fingerprint("o", "EXPOSURE_001", "svc2", "pan", "t"), fingerprint("o", "EXPOSURE_001", "svc", "x", "t"),
                    fingerprint("o", "EXPOSURE_001", "svc", "pan", "t2")):
        assert changed != base


# ---- grouping -----------------------------------------------------------------------------------

def test_a_flood_becomes_a_handful_of_incidents_and_every_verdict_stays_in_the_chain(store):
    kinds = ["payment failed for order {n} user={n}", "retry {n} of 5 for session {n}", "cache miss key {n}"]
    for n in range(900):
        _add(store, kinds[n % 3].format(n=n))
    summary = store.incident_summary(ORG)
    assert summary["verdicts"] == 900 and summary["verdicts_grouped"] == 900 and summary["incidents"] == 3
    rows, total = store.list_incidents(ORG)
    assert total == 3 and sorted(r["count"] for r in rows) == [300, 300, 300]
    assert store.verify_chain(ORG)["valid"] is True and store.count(ORG) == 900


def test_a_different_system_rule_or_field_is_a_different_incident(store):
    _add(store, source_system="a")
    _add(store, source_system="b")
    from schemas.models import RuleId
    _add(store, rule_id=RuleId.PURPOSE_001)
    assert store.incident_summary(ORG)["incidents"] == 3


def test_count_first_last_seen_severity_and_sparkline(store):
    from schemas.models import Severity
    _add(store, severity=Severity.LOW)
    _add(store, severity=Severity.HIGH)
    (row,), _ = store.list_incidents(ORG)
    assert row["count"] == 2 and row["severity"] == "HIGH" and row["first_seen"] <= row["last_seen"]
    assert len(row["sparkline"]) == inc.SPARK_HOURS and sum(row["sparkline"]) == 2 and row["sparkline"][-1] == 2


def test_other_organizations_never_see_or_share_incidents(store):
    _add(store, org="org_a")
    _add(store, org="org_b")
    (a,), _ = store.list_incidents("org_a")
    assert store.get_incident("org_b", a["incident_id"]) is None
    assert store.incident_summary("org_b")["incidents"] == 1
    with pytest.raises(ValueError):
        store.set_incident_status("org_b", a["incident_id"], "ACKNOWLEDGED")


def test_a_grouping_failure_keeps_the_verdict(store, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("no")
    monkeypatch.setattr(inc, "attach", boom)
    vid = _add(store)
    assert store.get_by_verdict_id(ORG, vid) is not None and store.verify_chain(ORG)["valid"] is True
    monkeypatch.undo()
    monkeypatch.setenv("VERITAS_INCIDENT_GRACE_SECONDS", "0")
    assert store.backfill_incidents(ORG) == 1 and store.incident_summary(ORG)["verdicts_grouped"] == 1


def test_grouping_can_be_turned_off(store, monkeypatch):
    monkeypatch.setenv("VERITAS_INCIDENTS", "off")
    _add(store)
    assert store.incident_summary(ORG)["incidents"] == 0 and store.count(ORG) == 1


# ---- status as chained events -------------------------------------------------------------------

def _events(store):
    out = []
    for r in store._conn.execute("SELECT payload_json FROM evidence WHERE tenant_id = ? AND record_type = ? "
                                 "ORDER BY row_index", (ORG, cn.INCIDENT_EVENT)):
        out.append(json.loads(decrypt_field(r["payload_json"])))
    return out


def test_status_changes_are_chained_events_with_who_and_why(store):
    _add(store)
    (row,), _ = store.list_incidents(ORG)
    store.set_incident_status(ORG, row["incident_id"], "ACKNOWLEDGED", actor="asha", reason="looking")
    out = store.set_incident_status(ORG, row["incident_id"], "RESOLVED", actor="asha", reason="fixed in 4.2")
    assert out["status"] == "RESOLVED" and out["resolved_at"]
    ev = _events(store)
    assert [(e["action"], e["old_status"], e["new_status"], e["actor"]) for e in ev] == [
        ("STATUS", "OPEN", "ACKNOWLEDGED", "asha"), ("STATUS", "ACKNOWLEDGED", "RESOLVED", "asha")]
    assert ev[1]["reason"] == "fixed in 4.2" and ev[1]["seq"] == 3
    assert store.verify_chain(ORG)["valid"] is True


def test_a_step_that_is_not_allowed_is_refused_and_writes_nothing(store):
    _add(store)
    (row,), _ = store.list_incidents(ORG)
    store.set_incident_status(ORG, row["incident_id"], "RESOLVED")
    with pytest.raises(ValueError):
        store.set_incident_status(ORG, row["incident_id"], "OPEN")
    with pytest.raises(ValueError):
        store.set_incident_status(ORG, row["incident_id"], "BOGUS")
    assert len(_events(store)) == 1


def test_a_changed_status_without_an_event_is_caught(store):
    _add(store)
    (row,), _ = store.list_incidents(ORG)
    store._conn.execute("UPDATE incidents SET status = 'RESOLVED' WHERE incident_id = ?", (row["incident_id"],))
    store._conn.commit()
    res = store.verify_chain_detail(ORG)
    assert res["valid"] is False and res["reason"] == "STATUS_CACHE_MISMATCH"


# ---- regression ---------------------------------------------------------------------------------

def test_a_resolved_incident_reopens_as_recurred_when_the_finding_comes_back(store):
    _add(store)
    (row,), _ = store.list_incidents(ORG)
    store.set_incident_status(ORG, row["incident_id"], "RESOLVED", actor="asha")
    _add(store)
    out = store.get_incident(ORG, row["incident_id"])
    assert out["status"] == "OPEN" and out["recurred"] and out["recurred_count"] == 1 and out["count"] == 2
    recur = _events(store)[-1]
    assert (recur["action"], recur["old_status"], recur["new_status"], recur["actor"]) == ("RECUR", "RESOLVED", "OPEN", "system")
    assert store.verify_chain(ORG)["valid"] is True
    store.set_incident_status(ORG, row["incident_id"], "RESOLVED")      # and it can be resolved again
    _add(store)
    assert store.get_incident(ORG, row["incident_id"])["recurred_count"] == 2


def test_a_straggler_inside_the_grace_period_does_not_reopen(store, monkeypatch):
    monkeypatch.setenv("VERITAS_INCIDENT_GRACE_SECONDS", "3600")
    _add(store)
    (row,), _ = store.list_incidents(ORG)
    store.set_incident_status(ORG, row["incident_id"], "RESOLVED")
    _add(store)
    out = store.get_incident(ORG, row["incident_id"])
    assert out["status"] == "RESOLVED" and not out["recurred"] and out["count"] == 2
    assert [e["action"] for e in _events(store)] == ["STATUS"]


def test_a_recur_event_that_nothing_resolved_is_caught_by_the_check(store):
    _add(store)
    (row,), _ = store.list_incidents(ORG)
    store._append_event(ORG, cn.INCIDENT_EVENT, row["incident_id"], lambda e, s: cn.incident_event_body(
        ORG, s, e, row["incident_id"], "RECUR", "RESOLVED", "OPEN", "system", None, __import__("datetime").datetime.now()))
    store._conn.commit()
    assert store.verify_chain_detail(ORG)["reason"] == "EVENT_INVALID"


# ---- merge and split ----------------------------------------------------------------------------

def test_merge_moves_verdicts_and_future_lines_follow(store):
    _add(store, "payment failed for order 1")
    _add(store, "payment declined for order 1")
    _add(store, "payment declined for order 2")
    rows, _ = store.list_incidents(ORG)
    by_count = {r["count"]: r for r in rows}
    target, source = by_count[1], by_count[2]
    out = store.merge_incidents(ORG, source["incident_id"], target["incident_id"], actor="asha", reason="same bug")
    assert out["count"] == 3 and store.list_incidents(ORG)[1] == 1
    _add(store, "payment declined for order 3")
    assert store.get_incident(ORG, target["incident_id"])["count"] == 4
    assert store.get_incident(ORG, source["incident_id"])["merged_into"] == target["incident_id"]
    merge = [e for e in _events(store) if e["action"] == "MERGE"][0]
    assert merge["other_id"] == source["incident_id"] and merge["moved"] == 2
    assert store.verify_chain(ORG)["valid"] is True
    with pytest.raises(ValueError):
        store.set_incident_status(ORG, source["incident_id"], "ACKNOWLEDGED")


def test_split_moves_chosen_verdicts_into_a_new_incident(store):
    ids = [_add(store) for _ in range(5)]
    (row,), _ = store.list_incidents(ORG)
    new = store.split_incident(ORG, row["incident_id"], ids[:2], actor="asha", reason="different customer")
    assert new["count"] == 2 and store.get_incident(ORG, row["incident_id"])["count"] == 3
    assert {v["verdict_id"] for v in store.incident_verdicts(ORG, new["incident_id"])} == set(ids[:2])
    _add(store)                                                        # new lines still go to the original
    assert store.get_incident(ORG, row["incident_id"])["count"] == 4
    assert store.verify_chain(ORG)["valid"] is True
    with pytest.raises(ValueError):
        store.split_incident(ORG, row["incident_id"], ["not-a-verdict"])


def test_cannot_split_everything_or_merge_into_itself(store):
    ids = [_add(store) for _ in range(2)]
    (row,), _ = store.list_incidents(ORG)
    with pytest.raises(ValueError):
        store.split_incident(ORG, row["incident_id"], ids)
    with pytest.raises(ValueError):
        store.merge_incidents(ORG, row["incident_id"], row["incident_id"])


# ---- older findings -----------------------------------------------------------------------------

def test_findings_stored_before_grouping_are_grouped_by_rule_system_and_field(store, monkeypatch):
    monkeypatch.setenv("VERITAS_INCIDENTS", "off")
    for _ in range(4):
        store.append(_make_explained_verdict(tenant_id=ORG))
    store.append(_make_explained_verdict(tenant_id=ORG, source_system="other"))
    monkeypatch.setenv("VERITAS_INCIDENTS", "on")
    assert store.backfill_incidents(ORG) == 5
    rows, total = store.list_incidents(ORG)
    assert total == 2 and sorted(r["count"] for r in rows) == [1, 4]
    assert all(r["template"] == inc.LEGACY_TEMPLATE for r in rows)
    assert store.backfill_incidents(ORG) == 0
    assert store.verify_chain(ORG)["valid"] is True


def test_the_incident_events_are_in_the_export_for_the_stand_alone_verifier(store):
    _add(store)
    (row,), _ = store.list_incidents(ORG)
    store.set_incident_status(ORG, row["incident_id"], "RESOLVED", actor="asha")
    kinds = [r.get("record_type") or r.get("type") for r in (json.loads(x) if isinstance(x, str) else x
                                                              for x in store.export_records(ORG))]
    assert cn.INCIDENT_EVENT in kinds
