"""
"Why did this fire": the conditions of a rule, each answered, built from what the engine knew when it decided.

The trace is kept beside the finding (table verdict_trace), outside the signed record, so the chain's format is unchanged. It
holds names, kinds of data, counts and dates, never a value from the data. The signed record carries the rule id; the trace
carries the rule's version and each clause with the answer, so a reviewer can see whether the rule was applied correctly.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from rulebook import specs


def _clause(text: str, matched: bool, detail: Optional[str] = None) -> Dict[str, Any]:
    c = {"clause": text, "matched": bool(matched)}
    if detail:
        c["detail"] = detail
    return c


def build(verdict, event, kind: Optional[str], computed_severity: str) -> Dict[str, Any]:
    rid = verdict.rule_id.value
    spec = specs.SPECS.get(rid)
    m = verdict.matched_registry_entry if isinstance(verdict.matched_registry_entry, dict) else {}
    src = event.source_type.value if event is not None else verdict.source.value
    system, field = verdict.source_system, verdict.field
    clauses: List[Dict[str, Any]] = []
    context: Dict[str, Any] = {"system": system, "field": field, "source": src, "kind_of_data": kind}
    if rid == "EXPOSURE_001":
        is_log = src == "log"
        clauses = [_clause(spec.looks_at[0], True,
                           "the event came from a log" if is_log else f"the declaration for {field} in {system} allows only de-identified data"),
                   _clause(spec.looks_at[1], True, f"detected a kind of personal data: {kind or 'unknown'}")]
    elif rid == "PURPOSE_001":
        if "schema_change" in m:
            clauses = [_clause(spec.looks_at[0], True, f"{m['schema_change']} ({m.get('category')})"),
                       _clause(spec.looks_at[1], True, "no declared field matches this column by name or by kind")]
        elif not m:
            clauses = [_clause(spec.looks_at[0], True, f"detected a kind of personal data: {kind or 'unknown'}"),
                       _clause(spec.looks_at[1], True, f"the policy declares nothing for {field} in {system}")]
        else:
            clauses = [_clause(spec.looks_at[0], True, f"detected a kind of personal data: {kind or 'unknown'}"),
                       _clause(spec.looks_at[1], True, f"the declaration for {field} in {system} does not allow what was seen "
                               f"(declared purpose: {m.get('declared_purpose')}, scope: {m.get('consent_scope')})")]
            context.update({"declared_purpose": m.get("declared_purpose"), "consent_scope": m.get("consent_scope")})
    elif rid == "RETENTION_001":
        days, declared = None, m.get("retention_days")
        try:
            since = datetime.fromisoformat(str(m.get("created_at")).replace("Z", "+00:00"))
            ref = event.timestamp if event is not None else verdict.timestamp
            days = (ref - since).days
        except (TypeError, ValueError):
            pass
        clauses = [_clause(spec.looks_at[0], declared is not None, f"declared retention: {declared} days"),
                   _clause(spec.looks_at[1], True, f"the data is {days} days old" if days is not None else "older than the declared period")]
        context.update({"retention_days": declared, "age_days": days})
    elif rid == "LINKAGE_001":
        clauses = [_clause(spec.looks_at[0], True, "fields together: " + ", ".join(m.get("fields_involved", [])))]
    elif rid == "ERASURE_001":
        clauses = [_clause(spec.looks_at[0], True, "request " + str(m.get("erasure_request", ""))), _clause(spec.looks_at[1], True)]
    elif rid == "NOTICE_001":
        clauses = [_clause(spec.looks_at[0], True), _clause(spec.looks_at[1], True, str(m.get("notice_gap", "")))]
    return {"rule_id": rid, "rule_version": spec.version if spec else 1, "title": spec.title if spec else rid,
            "clauses": clauses, "context": context, "engine_severity": computed_severity, "final_severity": verdict.severity.value,
            "overlay": None, "exception": None, "actions": ["alert"], "kept_as_evidence": spec.evidence_kept if spec else ""}


def dumps(t: Dict[str, Any]) -> str:
    return json.dumps(t, sort_keys=True, separators=(",", ":"))


def read(store, org: str, verdict_id: str) -> Optional[Dict[str, Any]]:
    with store._lock:
        r = store._conn.execute("SELECT trace_json FROM verdict_trace WHERE org = ? AND verdict_id = ?", (org, verdict_id)).fetchone()
    return json.loads(r["trace_json"]) if r else None


def write(store, org: str, verdict_id: str, version: int, trace: Dict[str, Any]) -> None:
    with store.writer() as conn:
        conn.execute("INSERT OR REPLACE INTO verdict_trace (verdict_id, org, rule_version, trace_json) VALUES (?, ?, ?, ?)",
                     (verdict_id, org, version, dumps(trace)))
