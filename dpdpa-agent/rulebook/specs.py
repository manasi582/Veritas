"""
The six rules of the engine, written down as data.

The checks themselves stay in code (rules/engine.py, schema_watch, notice_registry, subject_lookup): they are tested and
trusted. A spec says what each rule is called, what it looks at, how serious it is by default and how low an organization may
set it, what it does by default, what is kept as evidence, and how to word it. Everything an organization may change about a
rule is an overlay on a spec, and a change needs approval (rulebook/changes.py).

Wording: a rule shows a *possible control failure*, a technical signal. Whether something is a breach of the Act is for the
organization and its counsel. `statute_context` is shown beside a finding as context, never as a conclusion.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

SEVERITIES = ("LOW", "MEDIUM", "HIGH")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}
ACTIONS = ("alert", "redact", "require_review", "escalate")
# Kinds of data that never go below HIGH, whatever an organization sets (the same tier the engine uses).
HIGH_KINDS = frozenset({"aadhaar", "pan", "card", "passport", "voter"})


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    version: int
    title: str                      # what the finding is called
    summary: str                    # what it means in a sentence, in the careful wording
    looks_at: Tuple[str, ...]       # the clauses of the condition, in plain words (the trace answers each)
    default_severity: str           # "by data kind": the engine's tiers decide; shown to the reader
    action: str = "alert"
    statute_context: str = ""
    evidence_kept: str = "The rule, the system, the field, the kind of data and the time. Never the value itself."
    core: bool = True               # a core rule cannot be switched off
    overridable_actions: Tuple[str, ...] = ACTIONS


SPECS: Dict[str, RuleSpec] = {s.rule_id: s for s in (
    RuleSpec("EXPOSURE_001", 1, "Personal data where it should not be",
             "Personal data was seen in a place that should not carry it, such as a log or a system declared to hold only de-identified data. "
             "This is a possible control failure.",
             ("the event comes from a log, or the system's declaration allows only de-identified data here",
              "a kind of personal data was detected in it"),
             "by kind of data", statute_context="Relates to the security safeguards duty (section 8(5) of the Act). Counsel decides what follows."),
    RuleSpec("PURPOSE_001", 1, "Personal data without a matching declaration",
             "Personal data appears in a system or field the policy does not declare for it. This is a possible gap between what is declared and what runs.",
             ("a kind of personal data was observed (or a personal-data column was added)",
              "the policy has no declaration for it in this system"),
             "by kind of data", statute_context="Relates to purpose limitation (sections 4 and 6 of the Act). Counsel decides what follows."),
    RuleSpec("RETENTION_001", 1, "Data held longer than declared",
             "Data is still seen after the retention period the policy declares for it. This is a possible retention control failure.",
             ("the policy declares a retention period for the field in this system",
              "the data is older than that period"),
             "by kind of data", statute_context="Relates to storage limitation and erasure (section 8(7) of the Act). Counsel decides what follows."),
    RuleSpec("LINKAGE_001", 1, "Fields that identify a person together",
             "Fields that together could identify a person appeared in one event. This is a possible re-identification risk.",
             ("an event holds every field of a combination the policy names",),
             "MEDIUM"),
    RuleSpec("ERASURE_001", 1, "An erased identifier appeared again",
             "An identifier for which an erasure request was closed was seen again in a system. This is a possible failure of the erasure.",
             ("an erasure request for this identifier was closed", "the identifier was observed again"),
             "HIGH", statute_context="Relates to erasure (sections 8(7) and 12(3) of the Act). Counsel decides what follows."),
    RuleSpec("NOTICE_001", 1, "Data without a current notice",
             "A kind of personal data was seen in a system that no current notice recorded in the policy covers. This is a possible notice gap.",
             ("notices are recorded in the policy", "no current notice covers this kind of data in this system"),
             "MEDIUM", statute_context="Relates to notice (section 5 of the Act). Veritas checks coverage only, not whether a notice is adequate."),
)}


def rank(severity: str) -> int:
    return _RANK[severity]


def floor_for(rule_id: str, kind: Optional[str], computed: str) -> str:
    """
    The lowest severity an organization may set for this finding: never below HIGH for kinds in HIGH_KINDS, and never below
    HIGH where the engine itself made it HIGH for a rule that is HIGH by nature (ERASURE_001). Otherwise LOW.
    """
    if kind and kind.lower() in HIGH_KINDS:
        return "HIGH"
    if rule_id == "ERASURE_001":
        return "HIGH"
    return "LOW"


def spec_of(rule_id: str) -> RuleSpec:
    return SPECS[rule_id]


def public(rule_id: str) -> dict:
    s = SPECS[rule_id]
    return {"rule_id": s.rule_id, "version": s.version, "title": s.title, "summary": s.summary, "looks_at": list(s.looks_at),
            "default_severity": s.default_severity, "default_action": s.action, "statute_context": s.statute_context,
            "evidence_kept": s.evidence_kept, "core": s.core, "severity_floor": "HIGH for Aadhaar, PAN, card, passport and voter data; LOW otherwise"}
