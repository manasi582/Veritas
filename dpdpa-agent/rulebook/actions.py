"""
What a rule does besides raising a finding, when an approved overlay asks for it.

  alert            the finding and the existing alerts (the default; always available)
  require_review   once per incident, a task for the owner of the system; confirming it is a chain entry
  escalate         if the incident is still unacknowledged after N minutes, one more alert naming the owner's escalation contact
  redact           the agents of the organization are told to mask, hash or drop these kinds of data (stricter only), see redaction_for

There is no block action. Veritas never stops a request or a write.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from rulebook import changes
from subject_lookup import rights

logger = logging.getLogger("rulebook.actions")


def incident_of(store, org: str, verdict_id: str) -> Optional[str]:
    with store._lock:
        r = store._conn.execute("SELECT incident_id FROM verdict_incident WHERE tenant_id = ? AND verdict_id = ?", (org, verdict_id)).fetchone()
    return r["incident_id"] if r else None


def open_review(store, org: str, verdict, incident_id: Optional[str], owners: Dict[str, dict]) -> Optional[str]:
    """One review task per incident, however many findings it groups. Returns the request id when one was opened."""
    if not incident_id:
        return None
    with store._lock:
        if store._conn.execute("SELECT 1 FROM rule_reviews WHERE org = ? AND incident_id = ?", (org, incident_id)).fetchone():
            return None
    made = rights.create_review_task(store, org, verdict.source_system, owners,
                                     {"rule_id": verdict.rule_id.value, "incident_id": incident_id, "field": verdict.field,
                                      "severity": verdict.severity.value})
    with store.writer() as conn:
        conn.execute("INSERT OR IGNORE INTO rule_reviews (org, incident_id, request_id) VALUES (?, ?, ?)", (org, incident_id, made["request_id"]))
    return made["request_id"]


def escalate_due(store, org: str, owners: Dict[str, dict], send, now: Optional[datetime] = None) -> int:
    """For each rule whose approved overlay has the escalate action: incidents still OPEN after the stated minutes, once each."""
    now = now or datetime.now(timezone.utc)
    sent = 0
    for rule_id, overlay in changes.active(store, org).overlays.items():
        if "escalate" not in overlay.get("actions", []):
            continue
        cutoff = (now - timedelta(minutes=int(overlay.get("escalate_after_minutes", 60)))).isoformat()
        with store._lock:
            rows = store._conn.execute(
                "SELECT i.incident_id, i.number, i.source_system, i.field, i.severity FROM incidents i "
                "WHERE i.tenant_id = ? AND i.rule_id = ? AND i.status = 'OPEN' AND i.merged_into IS NULL AND i.first_seen <= ? "
                "AND NOT EXISTS (SELECT 1 FROM rule_escalations e WHERE e.org = i.tenant_id AND e.incident_id = i.incident_id)",
                (org, rule_id, cutoff)).fetchall()
        for r in rows:
            o = owners.get(r["source_system"]) or {}
            to = o.get("escalation_contact") or o.get("email") or o.get("team") or "the owner"
            try:
                send(f"Veritas: unacknowledged finding INC-{r['number']} ({org})",
                     f"INC-{r['number']} ({rule_id}, {r['severity']}) on {r['source_system']} / {r['field']} has been open for more than "
                     f"{overlay.get('escalate_after_minutes', 60)} minutes with no acknowledgement. Escalate to: {to}.",
                     {"org": org, "incident": r["number"], "rule": rule_id})
            except Exception:
                logger.warning("escalation alert failed", exc_info=True)
                continue
            with store.writer() as conn:
                conn.execute("INSERT OR IGNORE INTO rule_escalations (org, incident_id, escalated_at) VALUES (?, ?, ?)",
                             (org, r["incident_id"], now.isoformat()))
            sent += 1
    return sent


def redaction_for(store, org: str) -> Dict[str, str]:
    """kind -> mask|hash|drop, from approved overlays with the redact action. The strictest mode wins (drop > hash > mask)."""
    order = {"mask": 0, "hash": 1, "drop": 2}
    out: Dict[str, str] = {}
    for overlay in changes.active(store, org).overlays.values():
        if "redact" not in overlay.get("actions", []):
            continue
        for kind, mode in (overlay.get("redact_kinds") or {}).items():
            if kind not in out or order[mode] > order[out[kind]]:
                out[kind] = mode
    return out
