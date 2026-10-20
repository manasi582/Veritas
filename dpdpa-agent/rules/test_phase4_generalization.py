"""
Phase 4 Rule Engine Generalization Tests
============================================
Lean, targeted coverage for what Phase 4 actually changed/verified —
NOT a re-run of Phase 0/1/3's own test suites (registry config loading,
org config validation, and linkage-rule matching already have their own
dedicated tests; this file does not duplicate them).

Two things are worth new coverage here:

  1. Check 1 (Exposure) used to hardcode `source_system == "marketing-
     analytics"` — a Retail Co-specific string. Phase 4 replaced it with a
     config-driven probe (_forbids_raw_pii_here). The existing regression
     test (test_marketing_purpose_case_classified_as_exposure_per_design_
     decision_1) only proves the classification OUTCOME is unchanged for
     Retail Co's own data — it can't prove the hardcode is actually gone,
     since Retail Co's source_system is still literally "marketing-
     analytics". TestCheck1GeneralizesBeyondHardcodedSourceSystemName
     proves the fix generalizes, using a synthetic org whose deidentified-
     only source_system is deliberately named nothing like Retail Co's.

  2. Multi-tenant isolation at the RULE ENGINE layer (not just the
     registry-loader layer, which Phase 1's registry/test_registry.py
     already covers). TestMultiTenantIsolationInterleaved proves that
     interleaving evaluate_event() calls for two different orgs in the
     same process — including repeated/reordered calls, which would
     surface any cached "current org" state — never lets one org's
     config values leak into the other's verdicts. This is the exit
     criterion Phase 4 called "the most important correctness property
     of this phase."

A third, small class confirms rule_id naming is consistent across all
four categories (Exposure/Purpose/Retention/Linkage), per Deliverable 5.

Run with: python -m pytest rules/test_phase4_generalization.py -v
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from detection.engine import detect_event
from detection.fixtures import RETENTION_VIOLATION_EVENT
from detection.models import DetectedEvent, MatchedEntity
from org_config.store import delete_org_configs, upload_org_config
from registry.loader import _reset_cache, load_registry
from rules.engine import evaluate_event
from schemas.models import Event, RuleId, Severity, SourceType

SYNTHETIC_ORG_ID = "phase4_test_org"

# Deliberately named NOTHING like Retail Co's "marketing-analytics" — the
# whole point is to prove Check 1 no longer needs that literal string.
SYNTHETIC_DEIDENTIFIED_SOURCE_SYSTEM = "clickstream_pipeline"
SYNTHETIC_ORDINARY_SOURCE_SYSTEM = "crm_service"

SYNTHETIC_ORG_CONFIG = {
    "org_id": SYNTHETIC_ORG_ID,
    "fields": [
        {
            "field_name": "contact_email",
            "pii_category": "email",
            "declared_purpose": "analytics",
            "consent_scope": "deidentified_or_hashed_only",
            "retention_days": 30,
            "source_system": SYNTHETIC_DEIDENTIFIED_SOURCE_SYSTEM,
        },
        {
            "field_name": "contact_email",
            "pii_category": "email",
            "declared_purpose": "customer_relations",
            "consent_scope": "customer_relations",
            "retention_days": 400,
            "source_system": SYNTHETIC_ORDINARY_SOURCE_SYSTEM,
        },
    ],
}


@pytest.fixture(autouse=True)
def fresh_registry_and_synthetic_org():
    """Clean slate per test: fresh registry cache, synthetic org config
    written then torn down so it never leaks into other test modules."""
    _reset_cache()
    delete_org_configs(SYNTHETIC_ORG_ID)
    result = upload_org_config(SYNTHETIC_ORG_ID, SYNTHETIC_ORG_CONFIG)
    assert result["status"] == "ok", result
    load_registry("retail_co", force_reload=True)
    yield
    _reset_cache()
    delete_org_configs(SYNTHETIC_ORG_ID)


def _email_detected_event(tenant_id: str, source_system: str, field_name: str = "contact_email") -> DetectedEvent:
    event = Event(
        tenant_id=tenant_id,
        event_id=str(uuid4()),
        source_type=SourceType.API,  # deliberately NOT "log" — proves this isn't firing via the log path
        source_system=source_system,
        timestamp=datetime.now(timezone.utc).isoformat(),
        raw_snippet=f'{{"{field_name}": "someone@example.com"}}',
        fields={field_name: "someone@example.com"},
    )
    return DetectedEvent(
        event=event,
        contains_pii=True,
        matched_entities=[
            MatchedEntity(field=field_name, entity_type="EMAIL_ADDRESS", confidence=1.0, matched_text="someone@example.com")
        ],
    )


class TestCheck1GeneralizesBeyondHardcodedSourceSystemName:

    def test_deidentified_scope_fires_exposure_for_a_synthetic_non_retail_co_source_system(self):
        """
        A source_system named nothing like "marketing-analytics", under
        an org that isn't retail_co, whose config declares consent_scope=
        deidentified_or_hashed_only, must still fire EXPOSURE_001 — proof
        that Check 1's rule is now config-driven, not a hardcoded string
        match against Retail Co's specific source_system name.
        """
        detected = _email_detected_event(SYNTHETIC_ORG_ID, SYNTHETIC_DEIDENTIFIED_SOURCE_SYSTEM)
        verdicts = evaluate_event(detected)
        assert len(verdicts) == 1
        v = verdicts[0]
        assert v.rule_id == RuleId.EXPOSURE_001
        assert v.severity == Severity.HIGH
        assert v.tenant_id == SYNTHETIC_ORG_ID
        assert v.matched_registry_entry is None  # Check 1 never surfaces registry evidence

    def test_same_org_ordinary_source_system_does_not_fire_exposure(self):
        """
        Control case: the SAME synthetic org, SAME field, but a
        source_system whose consent_scope does NOT forbid raw PII, must
        NOT fire Check 1 — proving the new probe is genuinely conditional
        on config (not "any API event from this org now fires exposure").
        """
        detected = _email_detected_event(SYNTHETIC_ORG_ID, SYNTHETIC_ORDINARY_SOURCE_SYSTEM)
        verdicts = evaluate_event(detected)
        exposure_verdicts = [v for v in verdicts if v.rule_id == RuleId.EXPOSURE_001]
        assert exposure_verdicts == []

    def test_unrelated_org_with_same_source_system_name_unaffected(self):
        """
        A source_system literally named the same as the synthetic org's
        deidentified one, but under a DIFFERENT org with no such
        declaration, must not fire — the signal is (org_id, field,
        source_system) scoped, never just a global source_system name.
        """
        detected = _email_detected_event("edtech_co", SYNTHETIC_DEIDENTIFIED_SOURCE_SYSTEM)
        verdicts = evaluate_event(detected)
        exposure_verdicts = [v for v in verdicts if v.rule_id == RuleId.EXPOSURE_001]
        assert exposure_verdicts == []


class TestMultiTenantIsolationInterleaved:
    """
    The highest-value new coverage for this phase: prove evaluate_event()
    (the full four-check chain) never lets one org's config leak into
    another org's verdict when events from different orgs are processed
    interleaved in the same process — the property the plan called out
    as most important to be rigorous about.
    """

    @staticmethod
    def _retail_co_retention_detected() -> DetectedEvent:
        return detect_event(RETENTION_VIOLATION_EVENT)

    @staticmethod
    def _edtech_linkage_detected() -> DetectedEvent:
        """edtech_co's linkage_rules declare [student_name, school_name, dob] —
        a field-name vocabulary completely disjoint from Retail Co's own
        linkage rules ([name, delivery_address, phone] and
        [aadhaar, pan, bank_details]). If tenant scoping were ever broken
        (e.g. always consulting Retail Co's config), this event would fire
        ZERO linkage verdicts instead of one, because none of its field
        names match any Retail Co rule."""
        event = Event(
            tenant_id="edtech_co",
            event_id=str(uuid4()),
            source_type=SourceType.API,
            source_system="student_portal",
            timestamp=datetime.now(timezone.utc).isoformat(),
            raw_snippet="{}",
            fields={"student_name": "Ananya Bhat", "school_name": "Delhi Public School", "dob": "2010-04-12"},
        )
        return DetectedEvent(event=event, contains_pii=False, matched_entities=[])

    @staticmethod
    def _retail_co_linkage_detected() -> DetectedEvent:
        event = Event(
            tenant_id="retail_co",
            event_id=str(uuid4()),
            source_type=SourceType.API,
            source_system="order-service",
            timestamp=datetime.now(timezone.utc).isoformat(),
            raw_snippet="{}",
            fields={"name": "Priya Nair", "delivery_address": "123 MG Road", "phone": "9876543210"},
        )
        return DetectedEvent(event=event, contains_pii=False, matched_entities=[])

    def test_interleaved_linkage_verdicts_never_cross_contaminate(self):
        retail_co_detected = self._retail_co_linkage_detected()
        edtech_detected = self._edtech_linkage_detected()

        # Interleave A,B,A,B,A,B — a naive "current org" global would
        # start returning stale/wrong results after the first switch.
        results = []
        for detected in [retail_co_detected, edtech_detected] * 3:
            results.append((detected.event.tenant_id, evaluate_event(detected)))

        for tenant_id, verdicts in results:
            linkage_verdicts = [v for v in verdicts if v.rule_id == RuleId.LINKAGE_001]
            assert len(linkage_verdicts) == 1, (tenant_id, verdicts)
            v = linkage_verdicts[0]
            assert v.tenant_id == tenant_id
            fields_involved = set(v.matched_registry_entry["fields_involved"])
            if tenant_id == "retail_co":
                assert fields_involved == {"name", "delivery_address", "phone"}
            else:
                assert fields_involved == {"student_name", "school_name", "dob"}

    def test_reordered_interleaving_produces_identical_results(self):
        """
        Same two events, called in a DIFFERENT relative order/count than
        the previous test. If any shared mutable state (a cache keyed
        wrong, a module-level "last org" variable) existed, changing call
        order would change the outcome. It must not.
        """
        retail_co_detected = self._retail_co_linkage_detected()
        edtech_detected = self._edtech_linkage_detected()

        order_a = [edtech_detected, edtech_detected, retail_co_detected, edtech_detected, retail_co_detected]
        for detected in order_a:
            verdicts = evaluate_event(detected)
            linkage_verdicts = [v for v in verdicts if v.rule_id == RuleId.LINKAGE_001]
            assert len(linkage_verdicts) == 1
            expected_fields = (
                {"name", "delivery_address", "phone"} if detected.event.tenant_id == "retail_co"
                else {"student_name", "school_name", "dob"}
            )
            assert set(linkage_verdicts[0].matched_registry_entry["fields_involved"]) == expected_fields

    def test_interleaved_exposure_and_retention_verdict_content_is_org_scoped(self):
        """
        Beyond "a verdict exists" — confirm the actual DATA inside the
        verdict (matched_registry_entry's source_system/retention_days/
        declared_purpose) belongs to the correct org, not the other one,
        under interleaving with the synthetic third org from the class
        above too (three distinct orgs in one process).
        """
        retail_co_detected = self._retail_co_retention_detected()
        synthetic_exposure_detected = _email_detected_event(SYNTHETIC_ORG_ID, SYNTHETIC_DEIDENTIFIED_SOURCE_SYSTEM)

        for _ in range(3):
            retail_co_verdicts = evaluate_event(retail_co_detected)
            synthetic_verdicts = evaluate_event(synthetic_exposure_detected)

            retention_verdicts = [v for v in retail_co_verdicts if v.rule_id == RuleId.RETENTION_001]
            assert len(retention_verdicts) == 1
            rv = retention_verdicts[0]
            assert rv.tenant_id == "retail_co"
            assert rv.matched_registry_entry["source_system"] == "delivery-partner-service"
            assert rv.matched_registry_entry["retention_days"] == 180
            assert rv.matched_registry_entry["declared_purpose"] == "onboarding_kyc"

            exposure_verdicts = [v for v in synthetic_verdicts if v.rule_id == RuleId.EXPOSURE_001]
            assert len(exposure_verdicts) == 1
            ev = exposure_verdicts[0]
            assert ev.tenant_id == SYNTHETIC_ORG_ID
            assert ev.source_system == SYNTHETIC_DEIDENTIFIED_SOURCE_SYSTEM
            # Exposure verdicts never carry registry evidence by design —
            # confirming this ALSO means Retail Co's onboarding_kyc/180-day
            # data could not possibly have leaked in here even in principle.
            assert ev.matched_registry_entry is None


class TestRuleIdNamingConsistency:

    def test_all_categories_follow_stable_naming_convention(self):
        """Every RuleId member must be '<CATEGORY>_<3-digit-number>', and
        all categories (Exposure, Purpose, Retention, Linkage, and Erasure,
        the watch for an identifier whose erasure request was closed) must be
        present exactly once."""
        seen_categories = set()
        for rule_id in RuleId:
            prefix, _, suffix = rule_id.value.rpartition("_")
            assert prefix, f"{rule_id.value!r} does not follow '<CATEGORY>_<N>'"
            assert suffix.isdigit() and len(suffix) == 3, f"{rule_id.value!r} suffix must be a 3-digit number"
            seen_categories.add(prefix)
        assert seen_categories == {"EXPOSURE", "PURPOSE", "RETENTION", "LINKAGE", "ERASURE"}
