"""
Counters for the observed processing map (phase T3, docs/TRUST_VISIBILITY_PLAN.md).

For every event that contained personal data we count, per organization, source system, field, kind of data
(category) and destination: how many events, and when first and last seen. Counts only: no value, no line, no
identifier. The destination is a host name taken from the event when it names one, otherwise empty.

Counts are collected in memory and written in batches (a few seconds or a few hundred keys), off the request path.
A crash loses at most that batch of counts. They are not evidence and are not in the chain.
"""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

FLUSH_SECONDS = 5.0
FLUSH_KEYS = 200


def enabled() -> bool:
    return os.environ.get("VERITAS_FLOWS", "on").strip().lower() not in ("off", "0", "false", "no")


def create_tables(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS observed_flows (
            tenant_id     TEXT NOT NULL,
            source_system TEXT NOT NULL,
            field         TEXT NOT NULL,
            category      TEXT NOT NULL,
            destination   TEXT NOT NULL DEFAULT '',
            count         INTEGER NOT NULL DEFAULT 0,
            first_seen    TEXT NOT NULL,
            last_seen     TEXT NOT NULL,
            PRIMARY KEY (tenant_id, source_system, field, category, destination)
        )""")


class FlowCounter:
    def __init__(self, store) -> None:
        self._store = store
        self._lock = threading.Lock()
        self._pending: Dict[Tuple[str, str, str, str, str], List] = {}
        self._last_flush = time.monotonic()

    def record(self, tenant: str, source_system: str, observations: Iterable[Tuple[str, str]],
               destination: Optional[str] = None, at: Optional[datetime] = None) -> None:
        """One event: `observations` are (field, category) pairs found in it (each counts once)."""
        if not enabled():
            return
        stamp = (at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
        dest = destination or ""
        with self._lock:
            for field, category in set(observations):
                slot = self._pending.setdefault((tenant, source_system, field, category, dest), [0, stamp, stamp])
                slot[0] += 1
                slot[2] = stamp
            due = len(self._pending) >= FLUSH_KEYS or time.monotonic() - self._last_flush >= FLUSH_SECONDS
        if due:
            self.flush()

    def flush(self) -> int:
        with self._lock:
            batch, self._pending = self._pending, {}
            self._last_flush = time.monotonic()
        if not batch:
            return 0
        try:
            with self._store.writer() as conn:
                for (tenant, system, field, category, dest), (n, first, last) in batch.items():
                    conn.execute("""
                        INSERT INTO observed_flows (tenant_id, source_system, field, category, destination,
                                                    count, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(tenant_id, source_system, field, category, destination) DO UPDATE SET
                            count = count + excluded.count,
                            first_seen = MIN(first_seen, excluded.first_seen),
                            last_seen = MAX(last_seen, excluded.last_seen)""",
                                 (tenant, system, field, category, dest, n, first, last))
        except Exception:
            with self._lock:                      # keep the counts for the next try
                for key, (n, first, last) in batch.items():
                    slot = self._pending.setdefault(key, [0, first, last])
                    slot[0] += n
                    slot[1] = min(slot[1], first)
                    slot[2] = max(slot[2], last)
            raise
        return len(batch)


def rows(store, tenant: str) -> List[dict]:
    store.flows.flush()
    with store._lock:
        return [dict(r) for r in store._conn.execute(
            "SELECT source_system, field, category, destination, count, first_seen, last_seen "
            "FROM observed_flows WHERE tenant_id = ? ORDER BY source_system, category, field, destination", (tenant,))]
