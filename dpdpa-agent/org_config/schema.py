"""
Veritas DPDPA Agent — Org Config Schema (Phase 0)
==================================================
Defines the Pydantic models for the Org Config file format.

THIS IS THE PRODUCT'S ONBOARDING MECHANISM.
Every organisation that integrates Veritas does so by writing one YAML file
that conforms to this schema. If at any point application code branches on
org_id, that is a signal this schema is missing a field.

Schema shape (YAML):

    org_id: "edtech_co"

    identifiers:
      - name: apaar_id
        pattern: "^[A-Z0-9]{12}$"
        validator: none

    fields:
      - field_name: apaar_id
        pii_category: student_identifier
        declared_purpose: academic_records
        consent_scope: enrollment
        retention_days: 3650
        source_system: student_portal

    linkage_rules:
      - fields: [student_name, school_name, dob]
        risk: LINKAGE_RISK

WHAT IS EXPLICITLY OUT OF SCOPE IN PHASE 0:
  - PAN/Aadhaar validator implementations (Phase 2)
  - Linkage-risk evaluation (Phase 3)
  - `validator` field is validated for known names (stub registry),
    but the actual validation logic is NOT implemented here.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Stub validator name registry
#
# This is the org-config-facing ALLOWLIST of validator names an identifier
# may declare — it gates what an uploaded config is even allowed to say,
# independent of whether that validator is actually implemented yet.
#
# Phase 2 implements the real validation logic in the top-level
# `validators.py` module (is_valid_pan, is_valid_aadhaar, and a runtime-
# extensible validator_registry / register_validator / get_validator).
# Adding a new name here does NOT automatically register an implementation
# there (and vice versa) — the two are intentionally decoupled: this set
# controls what a config may reference, validators.py controls what
# actually runs. Detection gracefully falls back to pattern-match
# confidence (with a logged warning) if a config-declared name has no
# runtime implementation — see detection/engine.py's
# _resolve_validation_status.
# ---------------------------------------------------------------------------

KNOWN_VALIDATORS = frozenset({"none", "pan", "aadhaar"})

# Built-in pattern shorthand names (org configs may use these instead of raw regex)
BUILTIN_PATTERNS: dict[str, str] = {
    "indian_phone":  r"^[6-9]\d{9}$",
    "indian_pan":    r"^[A-Z]{5}[0-9]{4}[A-Z]$",
    "indian_aadhaar": r"^\d{4}\s?\d{4}\s?\d{4}$",
    "uuid":          r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
}


# ---------------------------------------------------------------------------
# OrgIdentifier — custom identifier types the org cares about
# ---------------------------------------------------------------------------

class OrgIdentifier(BaseModel):
    """
    Declares a custom PII identifier type this org cares about.

    - name: a short slug, e.g. 'apaar_id', 'pan', 'aadhaar'
    - pattern: a regex string OR a built-in pattern alias (see BUILTIN_PATTERNS).
      The validator checks that the regex compiles without error.
    - validator: one of the registered validator names. Phase 2 implements
      the actual checksum/structural validation. Phase 0 only validates
      that the name is a known validator slug.
    """

    name: str = Field(..., min_length=1, description="Short slug name for this identifier type.")
    pattern: str = Field(
        ...,
        min_length=1,
        description=(
            "A regex pattern string, or one of the built-in aliases: "
            f"{sorted(BUILTIN_PATTERNS.keys())}."
        ),
    )
    validator: str = Field(
        default="none",
        description=(
            "Validator name. One of: "
            + ", ".join(sorted(KNOWN_VALIDATORS))
            + ". Phase 2 implements the actual logic."
        ),
    )

    @field_validator("pattern", mode="before")
    @classmethod
    def resolve_and_compile_pattern(cls, v: str) -> str:
        """
        If v is a built-in alias, expand it. Then verify the resulting
        string compiles as a valid regex.
        """
        resolved = BUILTIN_PATTERNS.get(v, v)
        try:
            re.compile(resolved)
        except re.error as e:
            raise ValueError(
                f"pattern {v!r} is not a valid regex (or known built-in alias): {e}"
            )
        return resolved

    @field_validator("validator", mode="before")
    @classmethod
    def check_known_validator(cls, v: str) -> str:
        if v not in KNOWN_VALIDATORS:
            raise ValueError(
                f"validator {v!r} is not a registered validator name. "
                f"Known validators: {sorted(KNOWN_VALIDATORS)}. "
                f"(Phase 2 will register additional validators.)"
            )
        return v


# ---------------------------------------------------------------------------
# OrgField — org's PII fields, replaces the hardcoded registry tables
# ---------------------------------------------------------------------------

class OrgField(BaseModel):
    """
    Declares a single PII field this org collects: what it is, why it is
    collected, what it may be used for, and for how long.

    This replaces the hardcoded registry tables (customers, delivery_partners,
    etc.) from the v2 demo. The loader reads these and constructs RegistryEntry
    objects dynamically — no field name or source_system is ever hardcoded
    in Veritas application logic.
    """

    field_name: str = Field(
        ..., min_length=1,
        description="The data field name, e.g. 'apaar_id', 'phone', 'delivery_address'."
    )
    pii_category: str = Field(
        ..., min_length=1,
        description="PII category, e.g. 'student_identifier', 'phone', 'aadhaar', 'address'."
    )
    declared_purpose: str = Field(
        ..., min_length=1,
        description="The declared purpose for collecting this field, e.g. 'academic_records'."
    )
    consent_scope: str = Field(
        ..., min_length=1,
        description="The consent boundary for this field's use."
    )
    retention_days: int = Field(
        ..., gt=0,
        description="Positive integer: maximum days this field may be retained before it becomes a RETENTION_001 violation."
    )
    source_system: str = Field(
        ..., min_length=1,
        description=(
            "The source system this field flows through. Free-form string — "
            "the org defines their own system names. Must match exactly what "
            "their events carry in source_system."
        )
    )
    data_since: Optional[datetime] = Field(
        default=None,
        description=(
            "Optional ISO date/datetime: when the data this field covers in this "
            "source_system started being held. Retention (RETENTION_001) is "
            "measured from this date. If omitted, retention is measured from "
            "when this org config version was uploaded, i.e. data is treated as "
            "newly collected. Set it when onboarding a system that already holds "
            "older data."
        )
    )

    @field_validator("data_since", mode="before")
    @classmethod
    def parse_data_since(cls, v: Any) -> Any:
        """Accept YAML dates, datetimes and ISO strings; normalise to UTC-aware."""
        if v is None or v == "":
            return None
        if isinstance(v, datetime):
            dt = v
        elif isinstance(v, date):
            dt = datetime(v.year, v.month, v.day)
        elif isinstance(v, str):
            try:
                dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
            except ValueError as e:
                raise ValueError(f"data_since {v!r} is not a valid ISO date/datetime") from e
        else:
            raise ValueError(f"data_since must be an ISO date/datetime, got {type(v).__name__}")
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# LinkageRule — combination-risk rules (data only, not evaluated in Phase 0)
# ---------------------------------------------------------------------------

class LinkageRule(BaseModel):
    """
    Declares a set of quasi-identifiers that, when co-occurring in the same
    event, constitute a re-identification risk.

    PHASE 0: This is config data ONLY. Nothing evaluates these rules yet.
    Phase 3 will implement the linkage-risk detection logic.

    Example: fields=[student_name, school_name, dob] means that if all three
    appear in the same event, it should be flagged as LINKAGE_RISK even if
    no single field is a smoking gun.
    """

    fields: List[str] = Field(
        ...,
        min_length=2,
        description="At least 2 field names whose co-occurrence constitutes linkage risk.",
    )
    risk: str = Field(
        default="LINKAGE_RISK",
        description="The risk label for this combination. Defaults to 'LINKAGE_RISK'."
    )

    @field_validator("fields", mode="before")
    @classmethod
    def at_least_two_fields(cls, v: List[str]) -> List[str]:
        if len(v) < 2:
            raise ValueError(
                f"linkage_rules.fields must list at least 2 field names to form a "
                f"combination risk — got {len(v)}: {v!r}"
            )
        return v


class OrgOwner(BaseModel):
    """Who looks after a source system: shown on its incidents so a finding reaches a person, not a queue."""
    team: Optional[str] = Field(default=None, max_length=120)
    email: Optional[str] = Field(default=None, max_length=200)
    slack_channel: Optional[str] = Field(default=None, max_length=120)


# ---------------------------------------------------------------------------
# OrgConfig — the top-level org config document
# ---------------------------------------------------------------------------

class OrgConfig(BaseModel):
    """
    The top-level Org Config document. One of these per integrating organisation.

    An organisation uploads this once. Veritas reads it for every event that
    org sends — no code changes, no redeployment required.
    """

    org_id: str = Field(
        ...,
        pattern=r"^[a-z0-9_]+$",
        description="Unique organisation identifier. Must match ^[a-z0-9_]+$. Used as the partition key for all data."
    )
    identifiers: List[OrgIdentifier] = Field(
        default_factory=list,
        description="Custom identifier types this org cares about (beyond generic name/email/phone)."
    )
    fields: List[OrgField] = Field(
        ...,
        description="All PII fields this org collects, with purpose, scope, and retention metadata."
    )
    linkage_rules: List[LinkageRule] = Field(
        default_factory=list,
        description=(
            "Sets of fields that, when co-occurring in one event, constitute "
            "re-identification/linkage risk. Evaluated in Phase 3."
        )
    )

    schema_hints: Dict[str, str] = Field(
        default_factory=dict,
        description=("Corrections for the guess Veritas makes about database columns: a column name or pattern (for "
                     "example 'col_7' or '*_ref') mapped to a kind of personal data, or to 'none' for a column that is "
                     "not personal. Optional.")
    )
    owners: Dict[str, OrgOwner] = Field(
        default_factory=dict,
        description="Owning team and channel per source_system, shown on incidents. Optional."
    )

    @field_validator("schema_hints")
    @classmethod
    def validate_schema_hints(cls, v: Dict[str, str]) -> Dict[str, str]:
        if len(v) > 200:
            raise ValueError("schema_hints has more than 200 entries")
        for pattern, kind in v.items():
            if not re.match(r"^[A-Za-z0-9_.*?\[\]-]{1,80}$", pattern):
                raise ValueError(f"schema_hints: {pattern!r} is not a column name or pattern")
            if not re.match(r"^(none|[a-z_]{2,30})$", str(kind).lower()):
                raise ValueError(f"schema_hints: {kind!r} is not a kind of data (use e.g. phone, email, aadhaar, or none)")
        return v

    @field_validator("org_id", mode="before")
    @classmethod
    def validate_org_id_format(cls, v: str) -> str:
        if not isinstance(v, str) or not re.match(r"^[a-z0-9_]+$", v):
            raise ValueError(
                f"org_id {v!r} is invalid. It must be non-empty and match pattern '^[a-z0-9_]+$'."
            )
        return v

    @model_validator(mode="after")
    def check_no_duplicate_identifier_names(self) -> "OrgConfig":
        """
        Identifier name must be unique within an org's config.
        """
        seen: set[str] = set()
        duplicates: list[str] = []
        for ident in self.identifiers:
            if ident.name in seen:
                duplicates.append(ident.name)
            seen.add(ident.name)
        if duplicates:
            raise ValueError(
                f"org_config.identifiers contains duplicate identifier name(s): {duplicates}. "
                f"Each identifier name must be unique within an org's config."
            )
        return self

    @model_validator(mode="after")
    def check_no_duplicate_field_names(self) -> "OrgConfig":
        """
        (source_system, field_name) must be unique within an org's config.
        Duplicate (source_system, field_name) entries would cause ambiguous registry lookups.
        """
        seen: set[tuple[str, str]] = set()
        duplicates: list[str] = []
        for f in self.fields:
            key = (f.source_system, f.field_name)
            if key in seen:
                duplicates.append(f"{f.source_system}:{f.field_name}")
            seen.add(key)
        if duplicates:
            raise ValueError(
                f"org_config.fields contains duplicate (source_system, field_name) entries: "
                f"{duplicates}. Each field_name must be unique within its source_system."
            )
        return self

    @model_validator(mode="after")
    def check_linkage_rule_fields_declared(self) -> "OrgConfig":
        """
        Every field name referenced in a linkage_rule must be declared in fields.
        An undeclared field in a linkage rule is always a typo — flag it explicitly.
        """
        declared = {f.field_name for f in self.fields}
        for rule in self.linkage_rules:
            undeclared = [f for f in rule.fields if f not in declared]
            if undeclared:
                raise ValueError(
                    f"linkage_rule references field(s) not declared in org_config.fields: "
                    f"{undeclared}. Declare them in fields first, or fix the typo."
                )
        return self
