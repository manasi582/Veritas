"""Retention review (phase D): the arithmetic at the boundaries, what counts as still seen, tasks, recurrence and alerts."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from evidence_store.store import EvidenceStore
from org_config.schema import OrgConfig
from retention_review import review as rr
from subject_lookup import rights

ORG = "ret_org"
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def cfg(data_since=None, days=90, **extra):
    field = {"field_name": "phone", "pii_category": "phone", "declared_purpose": "calls", "consent_scope": "c",
             "retention_days": days, "source_system": "support"}
    if data_since:
        field["data_since"] = data_since
    return OrgConfig.model_validate({"org_id": ORG, "fields": [field,
        {"field_name": "email", "pii_category": "email", "declared_purpose": "x", "consent_scope": "c", "retention_days": 30,
         "source_system": "support"}], **extra})


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "data"))
    for v in ("VERITAS_RETENTION_WARN_DAYS", "VERITAS_RETENTION_OBSERVED_DAYS"):
        monkeypatch.delenv(v, raising=False)
    s = EvidenceStore(tmp_path / "e.db")
    yield s
    s.close()


def seen(store, system="support", category="phone", field="raw_snippet", first=T0, last=None):
    store.flows.record(ORG, system, [(field, category)], at=first)
    if last:
        store.flows.record(ORG, system, [(field, category)], at=last)


def status(store, c, now, field="phone"):
    return next(i for i in rr.review(store, ORG, c, now)["items"] if i["field"] == field)


def test_the_boundaries_of_the_period_are_exact(store):
    seen(store, first=T0, last=T0 + timedelta(days=89))        # phone first seen on day 0, 90-day period
    c = cfg()
    assert status(store, c, T0 + timedelta(days=10))["status"] == rr.WITHIN
    assert status(store, c, T0 + timedelta(days=75))["status"] == rr.WITHIN                 # 15 days left
    assert status(store, c, T0 + timedelta(days=76))["status"] == rr.DUE_SOON               # 14 days left
    assert status(store, c, T0 + timedelta(days=89))["status"] == rr.DUE_SOON
    assert status(store, c, T0 + timedelta(days=90))["status"] == rr.DUE_SOON               # due at this instant
    assert status(store, c, T0 + timedelta(days=90, seconds=1))["status"] == rr.OVERDUE       # past it, seen on day 89
    item = status(store, c, T0 + timedelta(days=91))
    assert item["status"] == rr.OVERDUE and item["days_left"] == -1 and item["clock_source"] == "first seen by Veritas"


def test_data_that_is_no_longer_seen_is_not_overdue(store):
    seen(store, first=T0, last=T0 + timedelta(days=20))
    c = cfg()
    assert status(store, c, T0 + timedelta(days=95))["status"] == rr.PAST_NOT_SEEN        # last seen 75 days ago
    seen(store, first=T0 + timedelta(days=94))                                              # and now it is seen again
    assert status(store, c, T0 + timedelta(days=95))["status"] == rr.OVERDUE


def test_the_policys_data_since_starts_the_clock_even_if_nothing_was_seen(store):
    c = cfg(data_since="2025-06-01")
    item = status(store, c, T0)
    assert item["status"] == rr.PAST_NOT_SEEN and item["clock_source"] == "policy data_since" and item["days_left"] < 0
    seen(store, first=T0 - timedelta(days=1))
    assert status(store, c, T0)["status"] == rr.OVERDUE                                     # past its window and still seen


def test_without_data_since_and_without_sightings_there_is_no_clock(store):
    item = status(store, cfg(), T0)
    assert item["status"] == rr.NOT_OBSERVED and item["due_at"] is None


def test_a_sighting_matches_by_field_name_or_by_kind(store):
    seen(store, category="phone", field="user.phone")                      # a payload field: matched by its leaf
    seen(store, category="email", field="raw_snippet")                     # a log line: matched by the kind
    c = cfg()
    assert status(store, c, T0 + timedelta(days=1), "phone")["first_seen"] and status(store, c, T0 + timedelta(days=1), "email")["first_seen"]


def test_other_systems_and_organizations_are_not_mixed(store):
    seen(store, system="elsewhere")
    seen(store, first=T0 - timedelta(days=500))
    assert status(store, cfg(), T0)["clock_starts"].startswith("2024")          # only this system's sighting counts
    assert rr.review(store, "another_org", cfg())["items"][0]["status"] == rr.NOT_OBSERVED


def test_settings_change_the_windows(store, monkeypatch):
    seen(store, first=T0, last=T0 + timedelta(days=80))
    monkeypatch.setenv("VERITAS_RETENTION_WARN_DAYS", "5")
    assert status(store, cfg(), T0 + timedelta(days=80))["status"] == rr.WITHIN
    monkeypatch.setenv("VERITAS_RETENTION_WARN_DAYS", "30")
    assert status(store, cfg(), T0 + timedelta(days=80))["status"] == rr.DUE_SOON
    monkeypatch.setenv("VERITAS_RETENTION_OBSERVED_DAYS", "1")
    assert status(store, cfg(), T0 + timedelta(days=95))["status"] == rr.PAST_NOT_SEEN


def test_the_summary_orders_the_worst_first(store):
    seen(store, first=T0, last=T0 + timedelta(days=100))
    out = rr.review(store, ORG, cfg(), T0 + timedelta(days=101))
    assert [i["field"] for i in out["items"]][0] == "phone" and out["summary"][rr.OVERDUE] == 1
    assert "never deletes" in out["note"]


# ---- tasks, confirmation, recurrence ---------------------------------------------------------------------------

def test_a_retention_task_is_one_task_per_system_and_a_chain_entry(store):
    r = rights.create_retention_task(store, ORG, ["support", "billing"], owners={"support": {"team": "Support"}}, actor="asha")
    assert r["type"] == "retention" and r["status"] == "OPEN" and r["requester_ref"].startswith("RET-")
    assert [(t["system"], t["owner"]) for t in r["tasks"]] == [("billing", "unassigned"), ("support", "Support")]
    assert [e["action"] for e in r["events"]] == ["CREATED", "TASKS_CREATED"] and store.verify_chain(ORG)["valid"] is True


def test_confirming_every_task_closes_it_without_a_watch(store):
    r = rights.create_retention_task(store, ORG, ["support"], actor="asha")
    r = rights.confirm_task(store, ORG, r["request_id"], "support", "ravi", "purged the tickets older than 90 days")
    assert r["status"] == "CLOSED" and r["watching"] is False and store.subjects.watched(ORG) == {}
    assert [e["action"] for e in r["events"]][-1] == "CLOSED" and store.verify_chain(ORG)["valid"] is True


def test_a_second_open_task_for_the_same_system_is_refused_until_the_first_closes(store):
    first = rights.create_retention_task(store, ORG, ["support"], actor="a")
    with pytest.raises(rights.RequestError, match="already an open retention task"):
        rights.create_retention_task(store, ORG, ["support"], actor="a")
    rights.confirm_task(store, ORG, first["request_id"], "support", "x")
    assert rights.create_retention_task(store, ORG, ["support"], actor="a")["status"] == "OPEN"


def test_the_review_shows_an_open_task_and_a_task_needs_a_system(store):
    seen(store, first=T0, last=T0 + timedelta(days=100))
    r = rights.create_retention_task(store, ORG, ["support"], actor="a")
    assert status(store, cfg(), T0 + timedelta(days=101))["task_request_id"] == r["request_id"]
    with pytest.raises(rights.RequestError):
        rights.create_retention_task(store, ORG, [], actor="a")


def test_data_still_seen_after_a_task_closed_is_overdue_again_and_can_be_tasked_again(store):
    seen(store, first=T0, last=T0 + timedelta(days=100))
    r = rights.create_retention_task(store, ORG, ["support"], actor="a")
    rights.confirm_task(store, ORG, r["request_id"], "support", "x")
    seen(store, first=T0 + timedelta(days=110))                                    # the same kind of data keeps arriving
    item = status(store, cfg(), T0 + timedelta(days=111))
    assert item["status"] == rr.OVERDUE and item["task_request_id"] is None
    assert rights.create_retention_task(store, ORG, ["support"], actor="a")["status"] == "OPEN"


def test_the_record_of_a_retention_task_is_titled_as_such(store):
    from subject_lookup import record
    r = rights.create_retention_task(store, ORG, ["support"], actor="a", detail=[{"system": "support", "field": "phone"}])
    body = record.build(store, ORG, r["request_id"])
    assert body["title"] == "Retention review record" and body["identifiers"][0]["category"] == "retention"
    assert record.to_pdf(body, record.sign(body)).startswith(b"%PDF")


# ---- alerts ------------------------------------------------------------------------------------------------------

def test_overdue_and_due_soon_reach_the_alerts_once(store, monkeypatch, tmp_path):
    import alerts
    import config_loader
    import evidence_store.store as store_module
    seen(store, first=datetime.now(timezone.utc) - timedelta(days=100), last=datetime.now(timezone.utc) - timedelta(days=1))
    seen(store, category="email", first=datetime.now(timezone.utc) - timedelta(days=20))
    monkeypatch.setattr(store_module, "get_store", lambda *a, **k: store)
    monkeypatch.setattr(config_loader, "load_org_config", lambda org: cfg())
    store.append  # noqa: B018
    from evidence_store.test_evidence_store import _make_explained_verdict
    store.append(_make_explained_verdict(tenant_id=ORG))                            # makes the organization known to the store
    problems = alerts.current_problems()
    assert f"retention_overdue_{ORG}" in problems and f"retention_due_soon_{ORG}" in problems
    assert "support (phone)" in problems[f"retention_overdue_{ORG}"] and "support (email)" in problems[f"retention_due_soon_{ORG}"]
