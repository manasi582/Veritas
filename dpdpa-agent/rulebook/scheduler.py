"""
A small loop that does the two time-based things rules need, every minute: end exceptions whose date has passed (a chained
EXPIRED event) and send escalations for incidents left unacknowledged too long. Both are cheap when nothing is configured.
"""
from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

logger = logging.getLogger("rulebook.scheduler")
INTERVAL_SECONDS = 60


def run_once(store, send: Optional[Callable] = None) -> dict:
    from config_loader import load_org_config
    from rulebook import actions, changes
    if send is None:
        import alerts
        send = alerts.send
    expired = escalated = 0
    for org in store.tenants():
        try:
            expired += changes.expire_due(store, org)
            try:
                owners = {k: v.model_dump() for k, v in (load_org_config(org).owners or {}).items()}
            except Exception:
                owners = {}
            escalated += actions.escalate_due(store, org, owners, send)
        except Exception:
            logger.warning("rule schedule failed for %s", org, exc_info=True)
    return {"expired": expired, "escalated": escalated}


def _loop(stop: threading.Event) -> None:
    from evidence_store.store import get_store
    while not stop.wait(INTERVAL_SECONDS):
        try:
            run_once(get_store())
        except Exception:
            logger.warning("rule schedule pass failed", exc_info=True)


def start() -> threading.Event:
    stop = threading.Event()
    threading.Thread(target=_loop, args=(stop,), name="veritas-rules", daemon=True).start()
    return stop
