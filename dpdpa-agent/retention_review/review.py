"""
Retention review: for each field the policy declares (system, field, `retention_days`, optional `data_since`), when does its
declared retention period run out, and is data of that kind still being seen in that system?

Veritas does not see data at rest. It sees what passes through logs, API payloads and schema statements. So the review says:

  within        the period has not run out
  due soon      it runs out within VERITAS_RETENTION_WARN_DAYS (default 14)
  overdue       the period has run out and data of this kind was seen in this system in the last
                VERITAS_RETENTION_OBSERVED_DAYS (default 7): someone should confirm it was purged or justify keeping it
  past, not seen   the period has run out but nothing has been seen lately (informational)
  not observed  nothing has ever been seen for it and `data_since` is not set, so there is no clock to run

The clock starts at `data_since` if the policy sets it, otherwise at the first time data of this kind was seen in the system.
It never deletes anything; "closed" means a person confirmed their system and the data was not seen again.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from evidence_store import flows as flow_store
from field_names import field_leaf

WITHIN, DUE_SOON, OVERDUE, PAST_NOT_SEEN, NOT_OBSERVED = "within", "due soon", "overdue", "past, not seen", "not observed"


def warn_days() -> int:
    try:
        return max(1, int(os.environ.get("VERITAS_RETENTION_WARN_DAYS", "14")))
    except ValueError:
        return 14


def observed_days() -> int:
    try:
        return max(1, int(os.environ.get("VERITAS_RETENTION_OBSERVED_DAYS", "7")))
    except ValueError:
        return 7


def _dt(text: str) -> datetime:
    d = datetime.fromisoformat(text)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _open_tasks(store, org: str) -> Dict[str, str]:
    """system -> id of an open retention request that has a task for it."""
    with store._lock:
        rows = store._conn.execute(
            "SELECT t.system, r.request_id FROM request_tasks t JOIN rights_requests r ON r.request_id = t.request_id "
            "WHERE r.org = ? AND r.type = 'retention' AND r.status = 'OPEN' AND t.status = 'OPEN'", (org,)).fetchall()
    return {r["system"]: r["request_id"] for r in rows}


def review(store, org: str, cfg, now: Optional[datetime] = None) -> dict:
    now = now or datetime.now(timezone.utc)
    warn, seen_window = warn_days(), observed_days()
    observed = flow_store.rows(store, org)
    tasks = _open_tasks(store, org)
    owners = {k: v.model_dump() for k, v in (getattr(cfg, "owners", None) or {}).items()}
    items: List[dict] = []
    for f in cfg.fields:
        rows = [r for r in observed if r["source_system"] == f.source_system
                and (field_leaf(r["field"]).lower() == f.field_name.lower() or r["category"] == f.pii_category.lower())]
        first = min((_dt(r["first_seen"]) for r in rows), default=None)
        last = max((_dt(r["last_seen"]) for r in rows), default=None)
        start = f.data_since or first
        item = {"system": f.source_system, "field": f.field_name, "category": f.pii_category,
                "retention_days": f.retention_days, "owner": owners.get(f.source_system),
                "first_seen": first.isoformat() if first else None, "last_seen": last.isoformat() if last else None,
                "clock_starts": start.isoformat() if start else None, "clock_source": None,
                "due_at": None, "days_left": None, "task_request_id": tasks.get(f.source_system)}
        if start is None:
            item["status"] = NOT_OBSERVED
        else:
            item["clock_source"] = "policy data_since" if f.data_since else "first seen by Veritas"
            due = start + timedelta(days=f.retention_days)
            item["due_at"], item["days_left"] = due.isoformat(), (due - now).days
            still_seen = last is not None and (now - last) <= timedelta(days=seen_window)
            if now > due:
                item["status"] = OVERDUE if still_seen else PAST_NOT_SEEN
            elif due - now <= timedelta(days=warn):
                item["status"] = DUE_SOON
            else:
                item["status"] = WITHIN
        items.append(item)
    order = {OVERDUE: 0, DUE_SOON: 1, PAST_NOT_SEEN: 2, WITHIN: 3, NOT_OBSERVED: 4}
    items.sort(key=lambda i: (order[i["status"]], i["days_left"] if i["days_left"] is not None else 10 ** 9))
    counts = {s: sum(1 for i in items if i["status"] == s) for s in order}
    return {"items": items, "summary": counts, "settings": {"warn_days": warn, "observed_days": seen_window},
            "note": ("Veritas does not see data at rest: 'overdue' means the declared period has run out and data of this kind "
                     "was still seen in the system lately. It never deletes anything; a closed task means a person confirmed "
                     "their system and the data was not seen again.")}
