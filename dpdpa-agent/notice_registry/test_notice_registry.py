"""Notice registry (phase E): coverage, status of notices, findings once per gap, the daily sweep, and policy validation."""
import uuid
from datetime import date, datetime, timedelta, timezone

import pytest

from evidence_store.store import EvidenceStore
from notice_registry import coverage
from org_config.schema import OrgConfig
from schemas.models import SourceType

ORG = "notice_org"
TODAY = date(2026, 6, 1)


def policy(notices=None, notice_id=None, extra_fields=()):
    f = {"field_name": "phone", "pii_category": "phone", "declared_purpose": "calls", "consent_scope": "c", "retention_days": 30,
         "source_system": "order-service"}
    if notice_id:
        f["notice_id"] = notice_id
    return OrgConfig.model_validate({"org_id": ORG, "fields": [f, *extra_fields], "notices": notices or []})


def notice(nid="n1", cats=("phone",), systems=("order-service",), effective="2026-01-01", review_by=None, retired=False, version="1"):
    n = {"notice_id": nid, "version": version, "effective_from": effective, "data_categories": list(cats), "systems": list(systems), "retired": retired}
    if review_by:
        n["review_by"] = review_by
    return n


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "data"))
    s = EvidenceStore(tmp_path / "e.db")
    yield s
    s.close()


def see(store, system, category, field="raw_snippet"):
    store.flows.record(ORG, system, [(field, category)])


def run(store, cfg, today=TODAY):
    return coverage.review(store, ORG, cfg, today)


# ---- status of a notice -------------------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs,expected", [
    ({}, coverage.CURRENT),
    ({"effective": "2026-06-01"}, coverage.CURRENT),                      # effective today
    ({"effective": "2026-06-02"}, coverage.NOT_YET),
    ({"review_by": "2026-06-01"}, coverage.CURRENT),                      # due for review today: not yet overdue
    ({"review_by": "2026-05-31"}, coverage.REVIEW_OVERDUE),
    ({"retired": True}, coverage.RETIRED),
])
def test_the_status_of_a_notice(store, kwargs, expected):
    assert run(store, policy([notice(**kwargs)]))["notices"][0]["status"] == expected


# ---- declared fields ------------------------------------------------------------------------------------------

def test_a_declared_field_is_covered_by_a_current_notice_for_its_system_and_kind(store):
    out = run(store, policy([notice()]))
    assert out["declared"][0]["covered"] is True and out["declared"][0]["covered_by"] == ["n1"]


@pytest.mark.parametrize("notices,reason", [
    ([notice(cats=("email",))], "no current notice lists phone"),
    ([notice(systems=("other-system",))], "no current notice lists phone"),
    ([notice(retired=True)], "no current notice lists phone"),
    ([notice(effective="2027-01-01")], "no current notice lists phone"),
    ([], "no current notice lists phone"),
])
def test_a_declared_field_is_not_covered_when_no_current_notice_matches(store, notices, reason):
    d = run(store, policy(notices))["declared"][0]
    assert d["covered"] is False and reason in d["gap"]


def test_a_wildcard_notice_covers_every_system(store):
    assert run(store, policy([notice(systems=("*",))]))["declared"][0]["covered"] is True


def test_a_field_that_names_its_notice_is_judged_by_that_notice(store):
    cfg = policy([notice("n1"), notice("n2", cats=("email",))], notice_id="n2")
    d = run(store, cfg)["declared"][0]
    assert d["covered"] is False and "notice n2 is not current, or does not list phone" in d["gap"]   # n1 covers phone, but the field names n2
    cfg = policy([notice("n1"), notice("n2", cats=("phone",), systems=("order-service",))], notice_id="n2")
    assert run(store, cfg)["declared"][0]["covered_by"] == ["n2"]


def test_a_notice_past_its_review_date_still_covers_but_is_reported(store):
    out = run(store, policy([notice(review_by="2026-05-01")]))
    assert out["declared"][0]["covered"] is True and out["summary"]["review_overdue"] == 1


def test_the_policy_refuses_a_duplicate_notice_id_or_an_unknown_one():
    with pytest.raises(Exception, match="duplicate notice_id"):
        policy([notice("n1"), notice("n1")])
    with pytest.raises(Exception, match="not in 'notices'"):
        policy([notice("n1")], notice_id="missing")
    with pytest.raises(Exception):
        policy([notice(cats=("Not A Kind!",))])
    with pytest.raises(Exception):
        policy([{**notice(), "systems": []}])


# ---- observed data ----------------------------------------------------------------------------------------------

def test_observed_data_is_covered_or_not(store):
    see(store, "order-service", "phone")
    see(store, "order-service", "email")
    out = run(store, policy([notice()]))
    by = {(o["system"], o["category"]): o for o in out["observed"]}
    assert by[("order-service", "phone")]["covered"] is True and by[("order-service", "email")]["covered"] is False
    assert out["summary"]["observed_uncovered"] == 1


def test_systems_without_a_current_notice_are_listed(store):
    see(store, "billing", "phone")
    assert run(store, policy([notice()]))["systems_without_notice"] == ["billing"]


def test_without_notices_the_check_is_off(store):
    see(store, "order-service", "phone")
    out = run(store, policy())
    assert out["enabled"] is False and all(not d["covered"] for d in out["declared"])


# ---- findings --------------------------------------------------------------------------------------------------

def gaps(store, cfg, system, cats):
    return coverage.gaps_for_event(store, ORG, cfg, system, cats, str(uuid.uuid4()), SourceType.LOG)


def test_an_uncovered_observation_is_a_finding_once_per_gap(store):
    cfg = policy([notice()])
    first = gaps(store, cfg, "order-service", ["email", "phone"])
    assert [(v.rule_id.value, v.field, v.source_system) for v in first] == [("NOTICE_001", "email", "order-service")]
    assert gaps(store, cfg, "order-service", ["email"]) == []                      # the same gap is not raised again


def test_a_covered_gap_is_closed_and_can_be_raised_again_if_it_reopens(store):
    uncovered = policy([notice()])
    covered = policy([notice(cats=("phone", "email"))])
    assert len(gaps(store, uncovered, "order-service", ["email"])) == 1
    assert gaps(store, covered, "order-service", ["email"]) == []                  # a notice now lists it: the gap is closed
    assert len(gaps(store, uncovered, "order-service", ["email"])) == 1            # the notice is withdrawn: a new finding


def test_nothing_is_raised_when_the_policy_has_no_notices(store):
    assert gaps(store, policy(), "order-service", ["phone", "email"]) == []


def test_other_organizations_have_their_own_gaps(store):
    cfg = policy([notice()])
    assert len(gaps(store, cfg, "order-service", ["email"])) == 1
    assert len(coverage.gaps_for_event(store, "other_org", cfg, "order-service", ["email"], str(uuid.uuid4()), SourceType.LOG)) == 1


def test_the_daily_sweep_raises_gaps_that_appear_without_new_data(store):
    from evidence_store.test_evidence_store import _make_explained_verdict  # noqa: F401
    see(store, "order-service", "phone")
    ok = policy([notice()])
    assert coverage.sweep(store, ORG, ok) == 0
    lapsed = policy([notice(retired=True)])                                      # the notice is retired: phone is now uncovered
    assert coverage.sweep(store, ORG, lapsed) == 1
    assert coverage.sweep(store, ORG, lapsed) == 0                               # and is raised once
    rows, total = store.list_incidents(ORG)
    assert total == 1 and rows[0]["rule_id"] == "NOTICE_001" and store.verify_chain(ORG)["valid"] is True


def test_the_finding_explains_what_it_checks_and_what_it_cannot(store):
    from llm_explainer.explainer import build_deferred_explanation
    v = gaps(store, policy([notice()]), "order-service", ["email"])[0]
    text = build_deferred_explanation(v).explanation
    assert "no current notice" in text
    assert "cannot tell whether the notice was shown" in text and "legally adequate" in text


def test_the_daily_sweep_obeys_the_rules_in_force_and_keeps_a_trace(store):
    from rulebook import changes, trace
    see(store, "order-service", "phone")
    ends = (datetime.now(timezone.utc) + timedelta(days=10)).date().isoformat()
    e = changes.propose(store, ORG, changes.EXCEPTION, {"rule_id": "NOTICE_001", "system": "order-service", "field": "*", "owner": "Orders",
                                                       "reason": "notice is being re-issued this month", "expires_at": ends}, "alice")
    changes.approve(store, ORG, e["change_id"], "bob")
    assert coverage.sweep(store, ORG, policy([notice(retired=True)])) == 0           # inside an approved exception: counted, not raised
    assert changes.exception_hits(store, ORG)[e["change_id"]] == 1
    changes.revoke(store, ORG, e["change_id"], "alice", "done")
    changes.invalidate(ORG)
    with store.writer() as conn:                                                       # the gap row from the first pass would block a repeat
        conn.execute("DELETE FROM notice_gaps WHERE org = ?", (ORG,))
    assert coverage.sweep(store, ORG, policy([notice(retired=True)])) == 1
    rows, _ = store.list_incidents(ORG)
    v = store.incident_verdicts(ORG, rows[0]["incident_id"])[0]
    t = trace.read(store, ORG, v["verdict_id"])
    assert t and t["rule_id"] == "NOTICE_001" and t["clauses"]
