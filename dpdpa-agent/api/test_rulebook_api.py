"""The rules endpoints: who may propose, who approves, single-admin self-approval, exceptions, and the 'why' of a finding."""
from datetime import datetime, timedelta, timezone

from api.test_anchors_api import ORG, client, isolated  # noqa: F401
from evidence_store.store import get_store
from evidence_store.test_evidence_store import _make_explained_verdict
from rulebook import trace
from user_store.models import UserRole


def ends(n=30):
    return (datetime.now(timezone.utc) + timedelta(days=n)).date().isoformat()


def propose(c, **kw):
    body = {"kind": "OVERLAY", "target": "EXPOSURE_001", "setting": {"severity": "MEDIUM"}, "reason": "we log less now"}
    return c.post(f"/v1/{ORG}/rules/changes", json={**body, **kw})


def test_rules_lists_the_six_with_their_wording_and_floor():
    r = client(UserRole.VIEWER, "v").get(f"/v1/{ORG}/rules").json()
    assert [x["rule_id"] for x in r["rules"]] == ["EXPOSURE_001", "PURPOSE_001", "RETENTION_001", "LINKAGE_001", "ERASURE_001", "NOTICE_001"]
    ex = r["rules"][0]
    assert "possible control failure" in ex["summary"] and ex["core"] is True and "Aadhaar" in ex["severity_floor"]
    assert all("violation" not in x["summary"].lower() for x in r["rules"])


def test_only_a_compliance_admin_proposes_and_approves():
    for role, name in ((UserRole.VIEWER, "v"), (UserRole.AUDITOR, "a")):
        c = client(role, name)
        assert propose(c).status_code == 403
        assert c.post(f"/v1/{ORG}/rules/changes/x/approve", json={}).status_code == 403
    assert client(UserRole.COMPLIANCE_ADMIN, "adm").get(f"/v1/{ORG}/rules/changes").status_code == 200


def test_a_second_administrator_approves_and_the_setting_takes_effect():
    a, b = client(UserRole.COMPLIANCE_ADMIN, "alice"), client(UserRole.COMPLIANCE_ADMIN, "bob")
    p = propose(a)
    assert p.status_code == 201 and p.json()["status"] == "PROPOSED"
    cid = p.json()["change_id"]
    assert a.post(f"/v1/{ORG}/rules/changes/{cid}/approve", json={}).status_code == 400          # not the same person, two admins exist
    done = b.post(f"/v1/{ORG}/rules/changes/{cid}/approve", json={"reason": "agreed"})
    assert done.status_code == 200 and done.json()["status"] == "APPROVED" and done.json()["self_approved"] is False
    rule = [x for x in a.get(f"/v1/{ORG}/rules").json()["rules"] if x["rule_id"] == "EXPOSURE_001"][0]
    assert rule["overlay"]["severity"] == "MEDIUM"
    assert get_store().verify_chain(ORG)["valid"] is True
    from audit_log.store import get_audit_store
    text = str(get_audit_store().query(limit=100))
    assert "RULE_CHANGE_PROPOSED" in text and "RULE_CHANGE_APPROVED" in text


def test_a_single_administrator_may_approve_their_own_change_and_it_is_flagged():
    only = client(UserRole.COMPLIANCE_ADMIN, "solo")
    assert only.get(f"/v1/{ORG}/rules").json()["self_approval_allowed"] is True
    cid = propose(only).json()["change_id"]
    r = only.post(f"/v1/{ORG}/rules/changes/{cid}/approve", json={})
    assert r.status_code == 200 and r.json()["self_approved"] is True


def test_bad_proposals_are_refused_with_a_reason():
    c = client(UserRole.COMPLIANCE_ADMIN, "adm")
    for body in ({"setting": {"enabled": False}}, {"setting": {"actions": ["block"]}}, {"target": "NOPE"}, {"kind": "SOMETHING"}):
        r = propose(c, **body)
        assert r.status_code == 400 and r.json()["detail"]
    r = propose(c, kind="EXCEPTION", target=None, setting={"rule_id": "EXPOSURE_001", "system": "*", "field": "*", "reason": "long enough reason",
                                                           "owner": "Orders", "expires_at": ends()})
    assert r.status_code == 400 and "narrow" in r.json()["detail"]


def test_exceptions_list_shows_findings_covered_and_revoking_ends_it():
    a, b = client(UserRole.COMPLIANCE_ADMIN, "alice"), client(UserRole.COMPLIANCE_ADMIN, "bob")
    cid = propose(a, kind="EXCEPTION", target=None, setting={"rule_id": "EXPOSURE_001", "system": "orders", "field": "*",
                                                             "reason": "known debug logging, being removed", "owner": "Orders team",
                                                             "expires_at": ends()}).json()["change_id"]
    b.post(f"/v1/{ORG}/rules/changes/{cid}/approve", json={})
    from rulebook import changes
    changes.count_exception_hit(get_store(), ORG, cid)
    rows = a.get(f"/v1/{ORG}/rules/exceptions").json()["exceptions"]
    assert len(rows) == 1 and rows[0]["findings_covered"] == 1
    assert b.post(f"/v1/{ORG}/rules/changes/{cid}/revoke", json={"reason": "done"}).json()["status"] == "REVOKED"
    assert a.get(f"/v1/{ORG}/rules/exceptions").json()["exceptions"] == []


def test_why_returns_the_trace_or_says_there_is_none():
    ev = _make_explained_verdict(tenant_id=ORG)
    get_store().append(ev)
    c = client(UserRole.VIEWER, "v")
    n = get_store().get_by_verdict_id(ORG, str(ev.verdict.verdict_id))["violation_id"]
    r = c.get(f"/v1/{ORG}/findings/{n}/why").json()
    assert r["recorded"] is False and r["rule"]["rule_id"] == "EXPOSURE_001"
    t = trace.build(ev.verdict, None, "pan", "HIGH")
    trace.write(get_store(), ORG, str(ev.verdict.verdict_id), 1, t)
    r = c.get(f"/v1/{ORG}/findings/{n}/why").json()
    assert r["recorded"] is True and r["trace"]["clauses"] and "counsel" in r["note"]
    assert c.get(f"/v1/{ORG}/findings/9999/why").status_code == 404
