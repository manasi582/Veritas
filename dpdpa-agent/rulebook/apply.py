"""
Applies the rules in force to the findings the engine produced, just before they are stored.

With nothing configured this changes nothing: the findings, their severity and their order are exactly the engine's (the tests
hold the old and the new path to the same answers). With an approved overlay, a finding's severity may be raised, or lowered down
to its floor; with an approved exception, a finding inside its scope (rule, system, field, until its end date) is not stored or
alerted, but is counted against the exception so it stays visible. A finding that is a possible breach candidate is never suppressed.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from rulebook import changes, specs, trace as tracing
from rules.sensitivity import entity_type_to_pii_category

logger = logging.getLogger("rulebook.apply")


@dataclass
class Decision:
    verdict: Any
    trace: Dict[str, Any]
    actions: List[str] = field(default_factory=lambda: ["alert"])
    suppressed_by: Optional[str] = None


def kind_of(verdict, matches) -> Optional[str]:
    m = verdict.matched_registry_entry if isinstance(verdict.matched_registry_entry, dict) else {}
    for key in ("pii_category", "category"):
        if m.get(key):
            return str(m[key]).lower()
    if verdict.rule_id.value == "NOTICE_001":
        return verdict.field.lower()
    for match in matches or ():
        if match.field == verdict.field:
            return entity_type_to_pii_category(match.entity_type)
    return None


def severity_after(overlay_severity: Optional[str], computed: str, rule_id: str, kind: Optional[str]) -> str:
    """Raise freely; lower only to the floor of the kind, and never above what the engine decided."""
    if not overlay_severity or overlay_severity == computed:
        return computed
    if specs.rank(overlay_severity) > specs.rank(computed):
        return overlay_severity
    floor = specs.floor_for(rule_id, kind, computed)
    lowest = overlay_severity if specs.rank(overlay_severity) >= specs.rank(floor) else floor
    return lowest if specs.rank(lowest) < specs.rank(computed) else computed


def apply(store, org: str, verdicts: List[Any], event, matches, now: Optional[datetime] = None) -> List[Decision]:
    """One Decision per finding, in the engine's order. A suppressed one has `suppressed_by` set and is not to be stored."""
    now = now or datetime.now(timezone.utc)
    try:
        in_force = changes.active(store, org)
    except Exception:
        logger.warning("could not read the rules in force; the engine's answers stand", exc_info=True)
        in_force = changes.Active({}, [])
    out: List[Decision] = []
    for v in verdicts:
        kind = kind_of(v, matches)
        computed = v.severity.value
        t = tracing.build(v, event, kind, computed)
        d = Decision(verdict=v, trace=t)
        overlay = in_force.overlays.get(v.rule_id.value)
        if overlay:
            new = severity_after(overlay.get("severity"), computed, v.rule_id.value, kind)
            if new != computed:
                d.verdict = v.model_copy(update={"severity": type(v.severity)(new)})
                t["final_severity"] = new
            d.actions = list(overlay.get("actions", ["alert"]))
            t["overlay"] = {"actions": d.actions, **({"severity": overlay["severity"]} if overlay.get("severity") else {}),
                            "note": "an approved setting of this organization"}
            t["actions"] = d.actions
        exc = in_force.exception_for(v.rule_id.value, v.source_system, v.field, now.date())
        if exc is not None:
            if v.breach_notification_candidate:
                t["exception"] = {"id": exc["change_id"], "number": exc["number"], "applied": False,
                                  "note": "an exception cannot cover a possible breach candidate; the finding stands"}
            else:
                d.suppressed_by = exc["change_id"]
                t["exception"] = {"id": exc["change_id"], "number": exc["number"], "applied": True, "ends": exc["setting"]["expires_at"],
                                  "reason": exc["setting"]["reason"], "owner": exc["setting"]["owner"]}
        out.append(d)
    return out
