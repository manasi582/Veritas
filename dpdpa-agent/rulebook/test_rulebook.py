"""Overlays, exceptions, approvals, the chain, the floors, the trace and the actions. No language model is needed."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from api.test_anchors_api import isolated  # noqa: F401  (the store fixture)
from detection.models import MatchedEntity
from evidence_store.store import get_store
from rulebook import actions, changes, specs, trace
from rulebook.apply import apply, kind_of, severity_after
from schemas.models import Event, RemediationStatus, RuleId, Severity, SourceType, Verdict

ORG = "rulebook_org"


def verdict(rule=RuleId.EXPOSURE_001, severity=Severity.HIGH, system="orders", field="phone", breach=False, entry=None):
    return Verdict(tenant_id=ORG, verdict_id=str(uuid.uuid4()), event_id=str(uuid.uuid4()), rule_id=rule, severity=severity,
                   source=SourceType.LOG, source_system=system, field=field, timestamp=datetime.now(timezone.utc),
                   matched_registry_entry=entry, breach_notification_candidate=breach,
                   remediation_status=RemediationStatus.OPEN, remediation_updated_at=None)


def event():
    return Event(event_id=str(uuid.uuid4()), tenant_id=ORG, source_type=SourceType.LOG, source_system="orders",
                 timestamp=datetime.now(timezone.utc), raw_snippet="x")


def match(field="phone", entity="IN_PHONE"):
    return MatchedEntity(field=field, entity_type=entity, matched_text="x", start=0, end=1, confidence=0.9, validation_status="pass")


def approved(store, kind, setting, target=None, who=("alice", "bob")):
    c = changes.propose(store, ORG, kind, setting, who[0], "because", target=target)
    return changes.approve(store, ORG, c["change_id"], who[1])


def in_days(n):
    return (datetime.now(timezone.utc) + timedelta(days=n)).date().isoformat()


# ---- nothing configured changes nothing ---------------------------------------------------------------------

def test_with_nothing_configured_the_engines_findings_stand_exactly():
    store = get_store()
    vs = [verdict(r, s) for r, s in ((RuleId.EXPOSURE_001, Severity.HIGH), (RuleId.PURPOSE_001, Severity.MEDIUM),
                                     (RuleId.RETENTION_001, Severity.LOW), (RuleId.NOTICE_001, Severity.MEDIUM))]
    out = apply(store, ORG, vs, event(), [match()])
    assert [d.verdict for d in out] == vs and not any(d.suppressed_by for d in out) and all(d.actions == ["alert"] for d in out)


# ---- severity ------------------------------------------------------------------------------------------------

def test_severity_can_be_raised_freely_and_lowered_only_to_the_floor():
    assert severity_after("HIGH", "LOW", "PURPOSE_001", "phone") == "HIGH"
    assert severity_after("LOW", "MEDIUM", "PURPOSE_001", "phone") == "LOW"
    assert severity_after("LOW", "HIGH", "EXPOSURE_001", "aadhaar") == "HIGH"       # never below HIGH for Aadhaar
    assert severity_after("MEDIUM", "HIGH", "EXPOSURE_001", "pan") == "HIGH"
    assert severity_after("LOW", "HIGH", "ERASURE_001", None) == "HIGH"
    assert severity_after("LOW", "HIGH", "EXPOSURE_001", "phone") == "LOW"
    assert severity_after("HIGH", "MEDIUM", "EXPOSURE_001", "card") == "HIGH"
    assert severity_after("LOW", "MEDIUM", "EXPOSURE_001", "card") == "MEDIUM"      # the engine's own answer is never raised by a floor


def test_an_approved_overlay_changes_severity_and_the_trace_says_so():
    store = get_store()
    approved(store, changes.OVERLAY, {"severity": "LOW"}, "EXPOSURE_001")
    out = apply(store, ORG, [verdict(field="phone"), verdict(field="aadhaar")], event(), [match("phone"), match("aadhaar", "IN_AADHAAR")])
    assert [d.verdict.severity.value for d in out] == ["LOW", "HIGH"]
    assert out[0].trace["engine_severity"] == "HIGH" and out[0].trace["final_severity"] == "LOW" and out[0].trace["overlay"]["severity"] == "LOW"
    assert out[1].trace["overlay"]["severity"] == "LOW" and out[1].trace["final_severity"] == "HIGH"


def test_the_newest_approved_overlay_wins_and_an_unapproved_one_does_nothing():
    store = get_store()
    approved(store, changes.OVERLAY, {"severity": "LOW"}, "EXPOSURE_001")
    changes.propose(store, ORG, changes.OVERLAY, {"severity": "MEDIUM"}, "alice", None, target="EXPOSURE_001")      # only proposed
    assert apply(store, ORG, [verdict()], event(), [match()])[0].verdict.severity.value == "LOW"
    approved(store, changes.OVERLAY, {"severity": "MEDIUM"}, "EXPOSURE_001")
    changes.invalidate(ORG)
    assert apply(store, ORG, [verdict()], event(), [match()])[0].verdict.severity.value == "MEDIUM"


def test_a_core_rule_cannot_be_switched_off_and_there_is_no_block_action():
    store = get_store()
    for bad in ({"enabled": False}, {"actions": ["block"]}, {"severity": "URGENT"}, {"actions": []}, {"actions": ["redact"]},
                {"actions": ["alert"], "redact_kinds": {"phone": "mask"}}, {"actions": ["redact"], "redact_kinds": {"phone": "erase"}},
                {"actions": ["escalate"], "escalate_after_minutes": 5}):
        with pytest.raises(changes.ChangeError):
            changes.propose(store, ORG, changes.OVERLAY, bad, "alice", None, target="EXPOSURE_001")
    with pytest.raises(changes.ChangeError):
        changes.propose(store, ORG, changes.OVERLAY, {"severity": "LOW"}, "alice", None, target="NO_SUCH_RULE")


# ---- approvals and the chain ---------------------------------------------------------------------------------

def test_a_different_person_must_approve_unless_self_approval_is_allowed_and_then_it_is_flagged():
    store = get_store()
    c = changes.propose(store, ORG, changes.OVERLAY, {"severity": "LOW"}, "alice", None, target="PURPOSE_001")
    with pytest.raises(changes.ChangeError):
        changes.approve(store, ORG, c["change_id"], "alice")
    done = changes.approve(store, ORG, c["change_id"], "alice", self_approval_allowed=True)
    assert done["status"] == "APPROVED" and done["self_approved"] is True
    assert store.verify_chain(ORG)["valid"] is True
    with pytest.raises(changes.ChangeError):
        changes.approve(store, ORG, c["change_id"], "bob")           # already decided


def test_reject_withdraw_and_who_may():
    store = get_store()
    a = changes.propose(store, ORG, changes.OVERLAY, {"severity": "LOW"}, "alice", None, target="PURPOSE_001")
    assert changes.reject(store, ORG, a["change_id"], "bob", "no")["status"] == "REJECTED"
    b = changes.propose(store, ORG, changes.OVERLAY, {"severity": "LOW"}, "alice", None, target="PURPOSE_001")
    with pytest.raises(changes.ChangeError):
        changes.withdraw(store, ORG, b["change_id"], "bob")
    assert changes.withdraw(store, ORG, b["change_id"], "alice")["status"] == "WITHDRAWN"
    assert store.verify_chain(ORG)["valid"] is True


def test_the_chain_notices_a_status_that_was_changed_in_the_table():
    store = get_store()
    c = changes.propose(store, ORG, changes.OVERLAY, {"severity": "LOW"}, "alice", None, target="PURPOSE_001")
    assert store.verify_chain(ORG)["valid"] is True
    with store.writer() as conn:
        conn.execute("UPDATE rule_changes SET status = 'APPROVED' WHERE change_id = ?", (c["change_id"],))
    r = store.verify_chain_detail(ORG)
    assert r["valid"] is False and r["reason"] == "STATUS_CACHE_MISMATCH"


# ---- exceptions ----------------------------------------------------------------------------------------------

def exc(**kw):
    base = {"rule_id": "EXPOSURE_001", "system": "orders", "field": "*", "reason": "known debug logging, being removed",
            "owner": "Orders team", "expires_at": in_days(30)}
    return {**base, **kw}


def test_an_exception_needs_a_scope_a_reason_an_owner_and_an_end_date_within_the_limit():
    store = get_store()
    for bad in (exc(system="*", field="*"), exc(expires_at=in_days(-1)), exc(expires_at=in_days(400)), exc(expires_at=""),
                exc(reason="short"), exc(owner=""), exc(rule_id="NOPE"), exc(system="a b;c"), {**exc(), "extra": 1}):
        with pytest.raises(changes.ChangeError):
            changes.propose(store, ORG, changes.EXCEPTION, bad, "alice")


def test_an_exception_suppresses_inside_its_scope_only_and_is_counted():
    store = get_store()
    e = approved(store, changes.EXCEPTION, exc(system="orders", field="phone*"))
    out = apply(store, ORG, [verdict(system="orders", field="phone"), verdict(system="billing", field="phone"),
                             verdict(system="orders", field="email"), verdict(RuleId.PURPOSE_001, system="orders", field="phone")],
                event(), [match()])
    assert [bool(d.suppressed_by) for d in out] == [True, False, False, False]
    assert out[0].trace["exception"]["applied"] and out[0].trace["exception"]["number"] == e["number"]
    changes.count_exception_hit(store, ORG, e["change_id"]); changes.count_exception_hit(store, ORG, e["change_id"])
    assert changes.exception_hits(store, ORG)[e["change_id"]] == 2


def test_a_possible_breach_candidate_is_never_suppressed():
    store = get_store()
    approved(store, changes.EXCEPTION, exc(system="orders", field="*"))
    d = apply(store, ORG, [verdict(breach=True, field="aadhaar")], event(), [match("aadhaar", "IN_AADHAAR")])[0]
    assert d.suppressed_by is None and d.trace["exception"]["applied"] is False


def test_an_exception_ends_on_its_date_can_be_revoked_and_expiry_is_chained():
    store = get_store()
    e = approved(store, changes.EXCEPTION, exc())
    assert apply(store, ORG, [verdict()], event(), [match()], now=datetime.now(timezone.utc))[0].suppressed_by
    later = datetime.now(timezone.utc) + timedelta(days=31)
    assert apply(store, ORG, [verdict()], event(), [match()], now=later)[0].suppressed_by is None      # past its date
    assert changes.expire_due(store, ORG, now=later) == 1 and changes.get(store, ORG, e["change_id"])["status"] == "EXPIRED"
    f = approved(store, changes.EXCEPTION, exc(field="x*"))
    assert changes.revoke(store, ORG, f["change_id"], "carol", "done")["status"] == "REVOKED"
    changes.invalidate(ORG)
    assert apply(store, ORG, [verdict(field="xyz")], event(), [match()])[0].suppressed_by is None
    assert store.verify_chain(ORG)["valid"] is True
    with pytest.raises(changes.ChangeError):
        changes.revoke(store, ORG, e["change_id"], "carol")                  # already expired


# ---- the trace -----------------------------------------------------------------------------------------------

def test_each_rule_has_a_trace_with_its_clauses_answered_and_no_value():
    cases = [(RuleId.EXPOSURE_001, None), (RuleId.PURPOSE_001, None), (RuleId.PURPOSE_001, {"schema_change": "ADD_COLUMN t.phone", "category": "phone"}),
             (RuleId.RETENTION_001, {"retention_days": 30, "created_at": "2020-01-01T00:00:00+00:00"}),
             (RuleId.LINKAGE_001, {"fields_involved": ["a", "b"]}), (RuleId.ERASURE_001, {"erasure_request": "r1"}),
             (RuleId.NOTICE_001, {"notice_gap": "orders:phone"})]
    for rule, entry in cases:
        t = trace.build(verdict(rule, entry=entry), event(), "phone", "HIGH")
        assert t["rule_id"] == rule.value and t["rule_version"] == 1 and t["clauses"] and all("matched" in c for c in t["clauses"])
    t = trace.build(verdict(RuleId.RETENTION_001, entry={"retention_days": 30, "created_at": "2020-01-01T00:00:00+00:00"}), event(), "phone", "MEDIUM")
    assert "declared retention: 30 days" in t["clauses"][0]["detail"] and "days old" in t["clauses"][1]["detail"]


def test_a_trace_can_be_stored_and_read_back():
    store = get_store()
    t = trace.build(verdict(), event(), "phone", "HIGH")
    trace.write(store, ORG, "v1", 1, t)
    assert trace.read(store, ORG, "v1") == t and trace.read(store, ORG, "nope") is None and trace.read(store, "other", "v1") is None


def test_every_rule_id_has_a_spec_and_kind_of_reads_the_right_place():
    assert set(specs.SPECS) == {r.value for r in RuleId}
    assert kind_of(verdict(entry={"pii_category": "PAN"}), []) == "pan"
    assert kind_of(verdict(RuleId.NOTICE_001, field="Phone"), []) == "phone"
    assert kind_of(verdict(field="aadhaar"), [match("aadhaar", "IN_AADHAAR")]) == "aadhaar"


# ---- actions -------------------------------------------------------------------------------------------------

def test_redaction_asks_take_the_strictest_mode_per_kind():
    store = get_store()
    approved(store, changes.OVERLAY, {"actions": ["alert", "redact"], "redact_kinds": {"phone": "mask", "aadhaar": "hash"}}, "EXPOSURE_001")
    approved(store, changes.OVERLAY, {"actions": ["redact"], "redact_kinds": {"phone": "drop"}}, "PURPOSE_001")
    changes.invalidate(ORG)
    assert actions.redaction_for(store, ORG) == {"phone": "drop", "aadhaar": "hash"}


def test_escalation_is_sent_once_per_old_open_incident():
    store = get_store()
    from incidents.template import template_of
    from evidence_store.test_evidence_store import _make_explained_verdict
    store.append(_make_explained_verdict(tenant_id=ORG), grouping=tuple(template_of("timeout calling payments")))
    approved(store, changes.OVERLAY, {"actions": ["alert", "escalate"], "escalate_after_minutes": 30}, "EXPOSURE_001")
    sent = []
    send = lambda subject, text, data=None: sent.append((subject, text))      # noqa: E731
    owners = {"order-service": {"escalation_contact": "head.of.eng@example.com"}}
    assert actions.escalate_due(store, ORG, owners, send) == 0                      # too new
    later = datetime.now(timezone.utc) + timedelta(hours=2)
    assert actions.escalate_due(store, ORG, owners, send, now=later) == 1
    assert actions.escalate_due(store, ORG, owners, send, now=later) == 0           # once
    assert "head.of.eng@example.com" in sent[0][1]


def test_a_review_task_is_opened_once_per_incident_and_confirming_it_is_chained():
    store = get_store()
    from incidents.template import template_of
    from evidence_store.test_evidence_store import _make_explained_verdict
    from subject_lookup import rights
    ev = _make_explained_verdict(tenant_id=ORG)
    store.append(ev, grouping=tuple(template_of("timeout calling payments")))
    iid = actions.incident_of(store, ORG, str(ev.verdict.verdict_id))
    assert iid
    owners = {"order-service": {"team": "Orders", "email": "o@example.com"}}
    first = actions.open_review(store, ORG, ev.verdict, iid, owners)
    assert first and actions.open_review(store, ORG, ev.verdict, iid, owners) is None
    req = rights.get_request(store, ORG, first)
    assert req["type"] == "review" and req["tasks"][0]["owner"].startswith("Orders")
    done = rights.confirm_task(store, ORG, first, "order-service", "alice", "checked")
    assert done["status"] == "CLOSED" and store.verify_chain(ORG)["valid"] is True


def test_the_scheduler_pass_expires_and_escalates_across_organizations():
    store = get_store()
    from incidents.template import template_of
    from evidence_store.test_evidence_store import _make_explained_verdict
    from rulebook import scheduler
    store.append(_make_explained_verdict(tenant_id=ORG), grouping=tuple(template_of("timeout calling payments")))
    e = approved(store, changes.EXCEPTION, exc())
    out = scheduler.run_once(store, send=lambda *a, **k: None)
    assert out == {"expired": 0, "escalated": 0} and changes.get(store, ORG, e["change_id"])["status"] == "APPROVED"
