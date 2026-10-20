"""
DPDPA Compliance Agent — Shared Pydantic Models (Phase 0 — Generalised)
========================================================================
These models are the Python-side contract for all inter-module communication.
They mirror /schemas/event_schema.json and /schemas/verdict_schema.json exactly.

WHAT CHANGED IN PHASE 0:
  - `SourceSystem` enum is REMOVED. `source_system` is now a free-form `str`
    whose valid values are whatever the org declares in their Org Config file.
    No Veritas core module should ever hardcode a specific source_system string
    in branching logic — that is always a signal the Org Config schema is
    missing a field.
  - `tenant_id: str` is added to both Event and Verdict. Every event and
    every verdict must be tagged with which organisation it belongs to.
    This is the multi-tenancy anchor for all downstream partitioning
    (registry lookups, Evidence Store queries, dashboard views).

FROZEN AFTER PHASE 0 — do not modify fields, enums, or validation rules
without a full team review. All later phases depend on these contracts.

IMMUTABILITY CONTRACT (enforced at application level from Phase 6 onwards):
  On a Verdict, only `remediation_status` and `remediation_updated_at` may
  ever be mutated after the record is written to the Evidence Store. Every
  other field (including tenant_id) is immutable and will form part of a
  SHA-256 hash chain. Do NOT write any code that mutates other Verdict
  fields post-write.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums — locked, do not extend without team review
# ---------------------------------------------------------------------------

class SourceType(str, Enum):
    """Whether the telemetry came from an application log or an API payload."""
    LOG = "log"
    API = "api"


# NOTE: SourceSystem enum has been deliberately removed in Phase 0.
# source_system is now a free-form str in both Event and Verdict.
# Valid values are org-defined — they come from the org's Org Config file.
# Any code that branches on a specific source_system string is hardcoding
# domain knowledge that belongs in config, not in application logic.


class RuleId(str, Enum):
    """
    The DPDPA compliance rules this agent enforces via telemetry.
    Out-of-scope rules (consent-notice validity, DPO governance, etc.) are
    documented in /docs/scope.md — do not add new rule IDs here without
    updating scope.md and the rule engine simultaneously.
    """
    EXPOSURE_001  = "EXPOSURE_001"   # PII exposed in log / API response
    PURPOSE_001   = "PURPOSE_001"    # Data used beyond declared consent purpose
    RETENTION_001 = "RETENTION_001"  # Data retained past consent expiry window
    LINKAGE_001   = "LINKAGE_001"    # Phase 3: quasi-identifier combination / linkage risk (rules/linkage.py)
    ERASURE_001   = "ERASURE_001"    # an identifier whose erasure request was closed was observed again (subject_lookup/)
    NOTICE_001    = "NOTICE_001"     # personal data was observed in a system that no current notice covers (notice_registry/)


class Severity(str, Enum):
    """Severity levels assigned by the Rule Engine."""
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"


class RemediationStatus(str, Enum):
    """
    Human follow-up status for a verdict.
    MUTABLE — the ONLY verdict field (along with remediation_updated_at)
    that may be changed after the verdict is written to the Evidence Store.
    This tracks human/engineering follow-up; it does NOT enact auto-remediation.
    """
    OPEN         = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED     = "RESOLVED"


# ---------------------------------------------------------------------------
# Event Model
# ---------------------------------------------------------------------------

class Event(BaseModel):
    """
    A single unit of telemetry ingested from an organisation's source system.
    Produced by the Ingestion Pipeline, consumed by PII Detection.

    All fields are immutable once the event is created — the raw_snippet
    especially must never be modified, as it is the primary audit evidence.

    Phase 0 additions:
      - tenant_id: required, identifies which org this event belongs to.
      - source_system: now a free-form str (org-defined), no longer a fixed enum.
    """

    tenant_id: str = Field(
        ...,
        min_length=1,
        description=(
            "The organisation this event belongs to. Must match a registered "
            "org_id in the Org Config store. All downstream partitioning "
            "(registry lookups, Evidence Store, dashboard) is scoped by this value."
        )
    )
    event_id: UUID = Field(
        ...,
        description="Globally unique identifier for this event (UUID v4)."
    )
    source_type: SourceType = Field(
        ...,
        description="Whether this event is a log line or an API payload."
    )
    source_system: str = Field(
        ...,
        min_length=1,
        description=(
            "The microservice or system that emitted this event. "
            "Free-form string — valid values are org-defined (from Org Config). "
            "Used to break down violations by system in the audit view."
        )
    )
    timestamp: datetime = Field(
        ...,
        description="ISO8601 UTC timestamp of when the event was emitted."
    )
    raw_snippet: str = Field(
        ...,
        min_length=1,
        description=(
            "The raw log line or API payload string as received. "
            "Never modify after ingestion — this is the audit evidence."
        )
    )
    fields: Dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Extracted key-value pairs from raw_snippet. "
            "Open map — different source systems carry different fields. "
            "Example: {'phone': '9876543210', 'apaar_id': 'AB12345678CD'}"
        )
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        """Accept ISO8601 strings and datetime objects."""
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        raise ValueError(f"timestamp must be ISO8601 string or datetime, got {type(v)}")

    model_config = {
        "json_schema_extra": {
            "example": {
                "tenant_id": "retail_co",
                "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "source_type": "log",
                "source_system": "order-service",
                "timestamp": "2026-08-21T10:34:12Z",
                "raw_snippet": "[2026-08-21 10:34:12] Payment processed for user {\"name\":\"Priya Nair\",\"pan\":\"ABCDE1234F\",\"amount\":5000}",
                "fields": {
                    "name": "Priya Nair",
                    "pan": "ABCDE1234F",
                    "amount": "5000"
                }
            }
        }
    }


# ---------------------------------------------------------------------------
# Verdict Model
# ---------------------------------------------------------------------------

class Verdict(BaseModel):
    """
    A compliance verdict produced by the Rule Engine for a single Event.

    IMMUTABILITY CONTRACT:
    ----------------------
    Only `remediation_status` and `remediation_updated_at` may be mutated
    after this record is written to the Evidence Store.
    All other fields (including tenant_id) are immutable and will be covered
    by a SHA-256 hash chain implemented in Phase 6. Any code that mutates
    other fields post-write is a bug and violates the audit integrity guarantee.

    Phase 0 additions:
      - tenant_id: required, immutable, inherited from triggering Event.
      - source_system: now a free-form str (org-defined), no longer a fixed enum.
    """

    # ------------------------------------------------------------------
    # IMMUTABLE fields — do not mutate after Evidence Store write
    # ------------------------------------------------------------------

    tenant_id: str = Field(
        ...,
        min_length=1,
        description=(
            "The organisation this verdict belongs to. Inherited from the "
            "triggering Event. Scopes all Evidence Store queries and dashboard "
            "views. IMMUTABLE."
        )
    )
    verdict_id: UUID = Field(
        ...,
        description="Globally unique identifier for this verdict (UUID v4). IMMUTABLE."
    )
    event_id: UUID = Field(
        ...,
        description="UUID of the Event that triggered this verdict. IMMUTABLE."
    )
    rule_id: RuleId = Field(
        ...,
        description="The DPDPA rule that was violated. IMMUTABLE."
    )
    severity: Severity = Field(
        ...,
        description="Severity assigned by the Rule Engine. IMMUTABLE."
    )
    source: SourceType = Field(
        ...,
        description="Source type inherited from the triggering Event. IMMUTABLE."
    )
    source_system: str = Field(
        ...,
        min_length=1,
        description=(
            "Source system inherited from the triggering Event. "
            "Free-form string — org-defined. "
            "Enables per-system breakdown in the audit view. IMMUTABLE."
        )
    )
    field: str = Field(
        ...,
        min_length=1,
        description=(
            "The specific PII field name that triggered this verdict. IMMUTABLE."
        )
    )
    timestamp: datetime = Field(
        ...,
        description="ISO8601 UTC timestamp of when this verdict was generated. IMMUTABLE."
    )
    matched_registry_entry: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "The consent registry entry that was matched or violated. "
            "Typed as dict stub — registry model defined separately. IMMUTABLE."
        )
    )
    breach_notification_candidate: bool = Field(
        ...,
        description=(
            "Whether this verdict qualifies for DPDPA breach notification "
            "to the Data Protection Board of India (72-hour window). IMMUTABLE."
        )
    )

    # ------------------------------------------------------------------
    # MUTABLE fields — ONLY these two may change after Evidence Store write
    # ------------------------------------------------------------------

    remediation_status: RemediationStatus = Field(
        default=RemediationStatus.OPEN,
        description=(
            "Human follow-up status. "
            "MUTABLE — one of only TWO fields allowed to change post Evidence Store write. "
            "Tracks human/engineering follow-up; does NOT enact auto-remediation."
        )
    )
    remediation_updated_at: Optional[datetime] = Field(
        default=None,
        description=(
            "Timestamp of last remediation_status update. Null until first change. "
            "MUTABLE — one of only TWO fields allowed to change post Evidence Store write."
        )
    )

    @field_validator("timestamp", "remediation_updated_at", mode="before")
    @classmethod
    def parse_timestamps(cls, v: Any) -> Optional[datetime]:
        """Accept ISO8601 strings and datetime objects."""
        if v is None:
            return None
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        raise ValueError(f"timestamp fields must be ISO8601 string or datetime, got {type(v)}")

    model_config = {
        "json_schema_extra": {
            "example": {
                "tenant_id": "retail_co",
                "verdict_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "rule_id": "EXPOSURE_001",
                "severity": "HIGH",
                "source": "log",
                "source_system": "order-service",
                "field": "pan",
                "timestamp": "2026-08-21T10:34:12.500Z",
                "matched_registry_entry": None,
                "breach_notification_candidate": True,
                "remediation_status": "OPEN",
                "remediation_updated_at": None
            }
        }
    }
