"""
Tests for Phase 6 — Evidence Store (updated for Phase 5+6 per-tenant scoping)

Critical tests:
  (a) Corrupt a row's content directly in the DB, confirm verify_chain() catches it.
  (b) Update a status, confirm verify_chain() still passes.

Every store method now requires tenant_id — all calls below pass it
explicitly ("retail_co", matching _make_explained_verdict's default) so this
file continues to exercise the single-tenant behavior it always has.
Cross-tenant isolation itself (two tenants' chains/queries never touching
each other) is covered separately in
rules/../api or the dedicated Phase 5+6 test file, not duplicated here.
"""

from __future__ import annotations

import pytest
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from schemas.models import (
    Verdict, RuleId, Severity, SourceType, RemediationStatus
)
from llm_explainer.explainer import ExplainedVerdict
from evidence_store.store import EvidenceStore

TENANT_ID = "retail_co"


def _make_explained_verdict(
    rule_id: RuleId = RuleId.EXPOSURE_001,
    source_system: str = "order-service",
    severity: Severity = Severity.HIGH,
    tenant_id: str = TENANT_ID,
) -> ExplainedVerdict:
    verdict = Verdict(
        tenant_id=tenant_id,
        verdict_id=uuid.uuid4(),
        event_id=uuid.uuid4(),
        rule_id=rule_id,
        severity=severity,
        source=SourceType.LOG,
        source_system=source_system,
        field="pan",
        timestamp=datetime.now(timezone.utc),
        matched_registry_entry=None,
        breach_notification_candidate=True,
        remediation_status=RemediationStatus.OPEN,
        remediation_updated_at=None,
    )
    return ExplainedVerdict(
        verdict=verdict,
        explanation="Test explanation",
        section_cited="DPDPA 2023 § 8(1) — Security Safeguards",
        confidence=0.9,
        used_fallback=False,
    )


@pytest.fixture
def tmp_store(tmp_path):
    """Fresh in-memory EvidenceStore backed by a temp file for each test."""
    db = tmp_path / "test_evidence.db"
    store = EvidenceStore(db_path=db)
    yield store
    store.close()


class TestHashChain:
    def test_empty_store_verifies(self, tmp_store):
        result = tmp_store.verify_chain(TENANT_ID)
        assert result["valid"] is True
        assert result["first_broken_index"] is None

    def test_single_row_verifies(self, tmp_store):
        ev = _make_explained_verdict()
        tmp_store.append(ev)
        result = tmp_store.verify_chain(TENANT_ID)
        assert result["valid"] is True

    def test_multiple_rows_verify(self, tmp_store):
        for _ in range(5):
            tmp_store.append(_make_explained_verdict())
        result = tmp_store.verify_chain(TENANT_ID)
        assert result["valid"] is True

    def test_corrupted_payload_detected(self, tmp_store):
        """
        CRITICAL TEST (a): Corrupt a row's payload_json directly in the DB.
        verify_chain() must catch it and report the correct broken index.
        """
        for _ in range(3):
            tmp_store.append(_make_explained_verdict())

        # Directly corrupt the first row's payload
        tmp_store._conn.execute(
            "UPDATE evidence SET payload_json = ? WHERE row_index = 1",
            ('{"tampered": "data"}',)
        )
        tmp_store._conn.commit()

        result = tmp_store.verify_chain(TENANT_ID)
        assert result["valid"] is False
        assert result["first_broken_index"] == 0  # 0-based, first row

    def test_corrupted_middle_row_detected(self, tmp_store):
        """Corruption in a middle row is detected at that row's index."""
        for _ in range(5):
            tmp_store.append(_make_explained_verdict())

        # Corrupt the 3rd row (row_index=3 in SQLite = index 2 in 0-based)
        tmp_store._conn.execute(
            "UPDATE evidence SET payload_json = ? WHERE row_index = 3",
            ('{"tampered": "middle"}',)
        )
        tmp_store._conn.commit()

        result = tmp_store.verify_chain(TENANT_ID)
        assert result["valid"] is False
        assert result["first_broken_index"] == 2  # 0-based

    def test_status_update_does_not_break_chain(self, tmp_store):
        """
        CRITICAL TEST (b): Update remediation_status, confirm verify_chain()
        still passes. The hash covers only immutable fields; mutable columns
        live outside it, so status updates must never affect chain validity.
        """
        ev = _make_explained_verdict()
        tmp_store.append(ev)
        verdict_id = str(ev.verdict.verdict_id)

        tmp_store.update_status(TENANT_ID, verdict_id, "ACKNOWLEDGED")

        result = tmp_store.verify_chain(TENANT_ID)
        assert result["valid"] is True

        tmp_store.update_status(TENANT_ID, verdict_id, "RESOLVED")
        result = tmp_store.verify_chain(TENANT_ID)
        assert result["valid"] is True

    def test_chain_intact_after_multiple_statuses_and_appends(self, tmp_store):
        evs = [_make_explained_verdict() for _ in range(4)]
        for ev in evs:
            tmp_store.append(ev)

        tmp_store.update_status(TENANT_ID, str(evs[0].verdict.verdict_id), "ACKNOWLEDGED")
        tmp_store.update_status(TENANT_ID, str(evs[1].verdict.verdict_id), "ACKNOWLEDGED")
        tmp_store.update_status(TENANT_ID, str(evs[1].verdict.verdict_id), "RESOLVED")

        result = tmp_store.verify_chain(TENANT_ID)
        assert result["valid"] is True


class TestStatusTransitions:
    def test_open_to_acknowledged(self, tmp_store):
        ev = _make_explained_verdict()
        tmp_store.append(ev)
        tmp_store.update_status(TENANT_ID, str(ev.verdict.verdict_id), "ACKNOWLEDGED")
        row = tmp_store.get_by_verdict_id(TENANT_ID, str(ev.verdict.verdict_id))
        assert row["remediation_status"] == "ACKNOWLEDGED"

    def test_acknowledged_to_resolved(self, tmp_store):
        ev = _make_explained_verdict()
        tmp_store.append(ev)
        vid = str(ev.verdict.verdict_id)
        tmp_store.update_status(TENANT_ID, vid, "ACKNOWLEDGED")
        tmp_store.update_status(TENANT_ID, vid, "RESOLVED")
        row = tmp_store.get_by_verdict_id(TENANT_ID, vid)
        assert row["remediation_status"] == "RESOLVED"

    def test_open_to_resolved_rejected(self, tmp_store):
        ev = _make_explained_verdict()
        tmp_store.append(ev)
        with pytest.raises(ValueError, match="Invalid status transition"):
            tmp_store.update_status(TENANT_ID, str(ev.verdict.verdict_id), "RESOLVED")

    def test_resolved_is_terminal(self, tmp_store):
        ev = _make_explained_verdict()
        tmp_store.append(ev)
        vid = str(ev.verdict.verdict_id)
        tmp_store.update_status(TENANT_ID, vid, "ACKNOWLEDGED")
        tmp_store.update_status(TENANT_ID, vid, "RESOLVED")
        with pytest.raises(ValueError, match="Invalid status transition"):
            tmp_store.update_status(TENANT_ID, vid, "ACKNOWLEDGED")

    def test_unknown_verdict_raises(self, tmp_store):
        with pytest.raises(ValueError, match="Verdict not found"):
            tmp_store.update_status(TENANT_ID, "non-existent-id", "ACKNOWLEDGED")


class TestQuery:
    def test_query_all(self, tmp_store):
        for _ in range(3):
            tmp_store.append(_make_explained_verdict())
        results = tmp_store.query(TENANT_ID)
        assert len(results) == 3

    def test_query_by_remediation_status(self, tmp_store):
        ev1 = _make_explained_verdict()
        ev2 = _make_explained_verdict()
        tmp_store.append(ev1)
        tmp_store.append(ev2)
        tmp_store.update_status(TENANT_ID, str(ev1.verdict.verdict_id), "ACKNOWLEDGED")

        open_results = tmp_store.query(TENANT_ID, remediation_status="OPEN")
        acknowledged_results = tmp_store.query(TENANT_ID, remediation_status="ACKNOWLEDGED")
        assert len(open_results) == 1
        assert len(acknowledged_results) == 1

    def test_query_by_source_system(self, tmp_store):
        ev_order = _make_explained_verdict(source_system="order-service")
        ev_marketing = _make_explained_verdict(source_system="marketing-analytics")
        tmp_store.append(ev_order)
        tmp_store.append(ev_marketing)

        results = tmp_store.query(TENANT_ID, source_system="order-service")
        assert len(results) == 1
        assert results[0]["source_system"] == "order-service"

    def test_query_by_severity(self, tmp_store):
        ev_high = _make_explained_verdict(severity=Severity.HIGH)
        ev_medium = _make_explained_verdict(severity=Severity.MEDIUM)
        tmp_store.append(ev_high)
        tmp_store.append(ev_medium)

        results = tmp_store.query(TENANT_ID, severity="HIGH")
        assert len(results) == 1
        assert results[0]["severity"] == "HIGH"

    def test_get_by_verdict_id(self, tmp_store):
        ev = _make_explained_verdict()
        tmp_store.append(ev)
        row = tmp_store.get_by_verdict_id(TENANT_ID, str(ev.verdict.verdict_id))
        assert row is not None
        assert row["verdict_id"] == str(ev.verdict.verdict_id)

    def test_get_by_unknown_id_returns_none(self, tmp_store):
        assert tmp_store.get_by_verdict_id(TENANT_ID, "nonexistent") is None

    def test_duplicate_verdict_id_rejected(self, tmp_store):
        ev = _make_explained_verdict()
        tmp_store.append(ev)
        with pytest.raises(sqlite3.IntegrityError):
            tmp_store.append(ev)


def _stats_verdict(rule: str, severity: str, system: str, breach: bool, tenant: str = "org_stats") -> ExplainedVerdict:
    ev = _make_explained_verdict(rule_id=RuleId(rule), source_system=system, severity=Severity(severity), tenant_id=tenant)
    ev.verdict.breach_notification_candidate = breach
    return ev


class TestStatsAreCountedByTheDatabase:
    """The overview must give the same numbers as reading every record, without reading any."""

    def _fill(self, store):
        for rule, sev, system, breach in [("EXPOSURE_001", "HIGH", "kyc", True), ("EXPOSURE_001", "HIGH", "kyc", False),
                                          ("PURPOSE_001", "MEDIUM", "orders", False), ("RETENTION_001", "LOW", "orders", False)]:
            store.append(_stats_verdict(rule, sev, system, breach))

    def test_same_numbers_as_reading_every_record(self, tmp_store):
        self._fill(tmp_store)
        got = tmp_store.stats("org_stats")
        rows = tmp_store.query("org_stats")
        assert got["total"] == len(rows) == 4
        assert got["by_rule"] == {"EXPOSURE_001": 2, "PURPOSE_001": 1, "RETENTION_001": 1}
        assert got["by_severity"] == {"HIGH": 2, "MEDIUM": 1, "LOW": 1}
        assert got["by_source_system"] == {"kyc": 2, "orders": 2}
        assert got["by_status"] == {"OPEN": 4} and got["breach_candidates"] == 1
        assert got["breach_candidates"] == sum(1 for r in rows if r.get("breach_notification_candidate"))

    def test_counting_does_not_decrypt_records(self, tmp_store, monkeypatch):
        self._fill(tmp_store)
        import evidence_store.store as mod
        def boom(*a, **k): raise AssertionError("a record was decrypted to count")
        monkeypatch.setattr(mod, "decrypt_field", boom)
        assert tmp_store.stats("org_stats")["total"] == 4

    def test_other_organizations_are_not_counted(self, tmp_store):
        self._fill(tmp_store)
        assert tmp_store.stats("someone_else")["total"] == 0

    def test_a_changed_summary_column_is_reported_as_tampering(self, tmp_store):
        self._fill(tmp_store)
        assert tmp_store.verify_chain("org_stats")["valid"] is True
        tmp_store._conn.execute("UPDATE evidence SET severity = 'LOW' WHERE row_index = 1")
        tmp_store._conn.commit()
        assert tmp_store.verify_chain("org_stats") == {"valid": False, "first_broken_index": 0}

    def test_an_existing_database_without_the_columns_is_filled_in_on_open(self, tmp_path):
        path = tmp_path / "old.db"
        s = EvidenceStore(path)
        s.append(_stats_verdict("EXPOSURE_001", "HIGH", "kyc", True))
        s.close()
        raw = sqlite3.connect(path)                       # make it look like it predates the columns
        raw.execute("UPDATE evidence SET rule_id = NULL, severity = NULL, source_system = NULL, breach_candidate = NULL")
        raw.commit(); raw.close()
        again = EvidenceStore(path)
        assert again.stats("org_stats")["by_severity"] == {"HIGH": 1}
        assert again.verify_chain("org_stats")["valid"] is True
        again.close()
