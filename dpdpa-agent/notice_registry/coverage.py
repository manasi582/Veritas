"""
Notice coverage. The policy lists the privacy notices in force (`notices:`: id, version, the kinds of data and the
systems each describes, effective date, review date). Veritas then answers three questions, as coverage and never as a
legal judgement:

  1. Is each **declared** field covered by a current notice for its system? (by the field's `notice_id` if it names one,
     otherwise by any current notice that lists the field's kind of data for that system)
  2. Is each kind of data **observed** in a system covered by a current notice for that system?
  3. Is each notice itself current? (not yet effective, retired, or past its review date)

A notice counts as *current* if it is effective, not retired, and not past `review_by` (a notice past its review date still
covers, but is flagged "review overdue" and is reported). An uncovered observation raises `NOTICE_001` once; it is raised
again only after the gap has been closed (covered) and has then reopened.

It cannot read a notice, cannot tell whether it is legally adequate, and cannot know whether it was shown to the person.
"""
from __future__ import annotations

import re
import uuid
from datetime import date, datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from evidence_store import flows as flow_store
from field_names import field_leaf
from schemas.models import RemediationStatus, RuleId, Severity, SourceType, Verdict

CURRENT, REVIEW_OVERDUE, NOT_YET, RETIRED = "current", "review overdue", "not yet effective", "retired"
_TOKENS = re.compile(r"[a-z0-9]+")


def create_tables(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notice_gaps (
            org TEXT NOT NULL, source_system TEXT NOT NULL, category TEXT NOT NULL,
            raised_at TEXT NOT NULL, closed_at TEXT, PRIMARY KEY (org, source_system, category))""")


def notice_status(n, today: date) -> str:
    if n.retired:
        return RETIRED
    if n.effective_from > today:
        return NOT_YET
    if n.review_by and today > n.review_by:
        return REVIEW_OVERDUE
    return CURRENT


def _covers_system(n, system: str) -> bool:
    return "*" in n.systems or system in n.systems


def _covering(notices, today: date, system: str, category: str, explicit: Optional[str] = None):
    out = []
    for n in notices:
        if notice_status(n, today) not in (CURRENT, REVIEW_OVERDUE) or not _covers_system(n, system):
            continue
        if (explicit is None or n.notice_id == explicit) and category in n.data_categories:
            out.append(n)
    return out


def _category_words(f) -> Set[str]:
    words = set(_TOKENS.findall(f.pii_category.lower())) | {f.pii_category.lower()}
    return words


def review(store, org: str, cfg, today: Optional[date] = None) -> dict:
    today = today or datetime.now(timezone.utc).date()
    notices = list(getattr(cfg, "notices", None) or [])
    out_notices = [{"notice_id": n.notice_id, "version": n.version, "title": n.title, "status": notice_status(n, today),
                    "effective_from": n.effective_from.isoformat(), "review_by": n.review_by.isoformat() if n.review_by else None,
                    "data_categories": n.data_categories, "systems": n.systems, "languages": n.languages} for n in notices]

    declared = []
    for f in cfg.fields:
        cats = _category_words(f)
        if f.notice_id:
            hit = [n for c in cats for n in _covering(notices, today, f.source_system, c, explicit=f.notice_id)]
            reason = None if hit else (f"notice {f.notice_id} is not current, or does not list {f.pii_category} for {f.source_system}")
        else:
            hit = [n for c in cats for n in _covering(notices, today, f.source_system, c)]
            reason = None if hit else f"no current notice lists {f.pii_category} for {f.source_system}"
        declared.append({"system": f.source_system, "field": f.field_name, "category": f.pii_category,
                         "notice_id": f.notice_id, "covered": bool(hit), "covered_by": sorted({n.notice_id for n in hit}), "gap": reason})

    observed: Dict[Tuple[str, str], dict] = {}
    for r in flow_store.rows(store, org):
        o = observed.setdefault((r["source_system"], r["category"]), {"system": r["source_system"], "category": r["category"],
                                                                       "events": 0, "first_seen": r["first_seen"], "last_seen": r["last_seen"]})
        o["events"] += r["count"]
        o["first_seen"], o["last_seen"] = min(o["first_seen"], r["first_seen"]), max(o["last_seen"], r["last_seen"])
    observed_list = []
    for (system, category), o in sorted(observed.items()):
        hit = _covering(notices, today, system, category)
        observed_list.append({**o, "covered": bool(hit), "covered_by": sorted(n.notice_id for n in hit)})

    systems_declared = {f.source_system for f in cfg.fields} | {o["system"] for o in observed_list}
    no_notice = sorted(s for s in systems_declared if not any(_covers_system(n, s) and notice_status(n, today) in (CURRENT, REVIEW_OVERDUE) for n in notices))
    summary = {"notices": len(notices), "declared_uncovered": sum(1 for d in declared if not d["covered"]),
               "observed_uncovered": sum(1 for o in observed_list if not o["covered"]),
               "review_overdue": sum(1 for n in out_notices if n["status"] == REVIEW_OVERDUE), "systems_without_notice": len(no_notice)}
    return {"enabled": bool(notices), "notices": out_notices, "declared": declared, "observed": observed_list,
            "systems_without_notice": no_notice, "summary": summary,
            "note": ("This checks that a current notice you have recorded covers the data the policy declares and the data Veritas "
                     "observes. It cannot read a notice, judge whether it is legally adequate, or know that it was shown to anyone.")}


# --------------------------------------------------------------------------- findings

def _new_gap_verdict(org: str, system: str, category: str, event_id: Optional[str] = None, source=SourceType.LOG) -> Verdict:
    return Verdict(
        tenant_id=org, verdict_id=str(uuid.uuid4()), event_id=event_id or str(uuid.uuid4()), rule_id=RuleId.NOTICE_001,
        severity=Severity.MEDIUM, source=source, source_system=system, field=category, timestamp=datetime.now(timezone.utc),
        matched_registry_entry={"notice_gap": f"{system}:{category}"}, breach_notification_candidate=False,
        remediation_status=RemediationStatus.OPEN, remediation_updated_at=None)


def gaps_for_event(store, org: str, cfg, system: str, categories, event_id: str, source) -> List[Verdict]:
    """
    NOTICE_001 for kinds of data just observed in `system` that no current notice covers, once per gap. Does nothing unless the
    policy lists notices. A gap that has since been covered is closed, so that it can be raised again if it reopens.
    """
    notices = list(getattr(cfg, "notices", None) or [])
    if not notices:
        return []
    today = datetime.now(timezone.utc).date()
    out: List[Verdict] = []
    now = datetime.now(timezone.utc).isoformat()
    with store.writer() as conn:
        for category in sorted(set(categories)):
            covered = bool(_covering(notices, today, system, category))
            row = conn.execute("SELECT closed_at FROM notice_gaps WHERE org = ? AND source_system = ? AND category = ?",
                               (org, system, category)).fetchone()
            if covered:
                if row is not None and row["closed_at"] is None:
                    conn.execute("UPDATE notice_gaps SET closed_at = ? WHERE org = ? AND source_system = ? AND category = ?",
                                 (now, org, system, category))
                continue
            if row is None or row["closed_at"] is not None:
                conn.execute("""INSERT INTO notice_gaps (org, source_system, category, raised_at, closed_at) VALUES (?, ?, ?, ?, NULL)
                                ON CONFLICT(org, source_system, category) DO UPDATE SET raised_at = excluded.raised_at, closed_at = NULL""",
                             (org, system, category, now))
                out.append(_new_gap_verdict(org, system, category, event_id, source))
    return out


def sweep(store, org: str, cfg) -> int:
    """The daily check: raises NOTICE_001 for every observed gap that has no finding yet (for example after a notice passed its
    review date or was retired), and closes gaps that are now covered. Returns how many findings were raised."""
    from llm_explainer.explainer import build_deferred_explanation
    from incidents.template import template_of
    found = review(store, org, cfg)
    if not found["enabled"]:
        return 0
    raised = 0
    for o in found["observed"]:
        verdicts = gaps_for_event(store, org, cfg, o["system"], [o["category"]], str(uuid.uuid4()), SourceType.LOG)
        for v in verdicts:
            store.append(build_deferred_explanation(v), grouping=tuple(template_of(f"no current notice covers {o['category']} in {o['system']}")))
            raised += 1
    return raised
