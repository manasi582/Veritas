"""
Veritas Audit Log Store
========================
Records every significant human administrative action for accountability.

This is separate from the Evidence Store (which records compliance violations).
The Audit Log records WHO did WHAT to the system and WHEN.

Actions logged:
  AUTH:   LOGIN, LOGOUT, LOGIN_FAILED, PASSWORD_CHANGED
  USERS:  USER_CREATED, USER_UPDATED, USER_DISABLED
  ORGS:   ORG_CREATED, ORG_UPDATED, ORG_ACCESS_GRANTED, ORG_ACCESS_REVOKED
  AGENTS: AGENT_KEY_ISSUED, AGENT_REGISTERED, AGENT_REVOKED
  DATA:   EVIDENCE_VIEWED, REPORT_EXPORTED, VIOLATION_ACKNOWLEDGED, VIOLATION_RESOLVED
  SYSTEM: CONFIG_CHANGED, LICENSE_CHECKED

Never logs:
  - Passwords, tokens, raw PII
  - Large payloads / request bodies
  - Evidence payload contents

Schema: audit.db → table `audit_log`
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger("audit_log.store")

_DEFAULT_DB_PATH: Path


def _init_default_path() -> Path:
    from runtime_paths import data_root
    return data_root() / "audit.db"


_DEFAULT_DB_PATH = _init_default_path()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogStore:
    """Append-only audit log. Writes are fire-and-forget (best-effort)."""

    def __init__(self, db_path: Path = _DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    log_id      TEXT PRIMARY KEY,
                    timestamp   TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    actor_id    TEXT,
                    actor_name  TEXT,
                    org_id      TEXT,
                    resource    TEXT,
                    result      TEXT NOT NULL DEFAULT 'SUCCESS',
                    detail      TEXT,
                    ip_address  TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_actor     ON audit_log(actor_id);
                CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_log(action);
                CREATE INDEX IF NOT EXISTS idx_audit_org       ON audit_log(org_id);
            """)
            self._conn.commit()

    def log(
        self,
        action: str,
        *,
        actor_id: Optional[str] = None,
        actor_name: Optional[str] = None,
        org_id: Optional[str] = None,
        resource: Optional[str] = None,
        result: str = "SUCCESS",
        detail: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Append an audit log entry. Never raises — failures are logged but swallowed."""
        try:
            if ip_address is None:
                from request_context import current_client_ip
                ip_address = current_client_ip()
            detail_json = json.dumps(detail, default=str) if detail else None
            with self._lock:
                self._conn.execute(
                    """
                    INSERT INTO audit_log
                        (log_id, timestamp, action, actor_id, actor_name,
                         org_id, resource, result, detail, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid4()), _now(), action,
                        actor_id, actor_name, org_id, resource,
                        result, detail_json, ip_address,
                    ),
                )
                self._conn.commit()
        except Exception as e:
            logger.warning("Audit log write failed (non-fatal): %s", e)

    def query(
        self,
        *,
        action: Optional[str] = None,
        actor_id: Optional[str] = None,
        org_id: Optional[str] = None,
        result: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query audit log entries with optional filters. Returns newest first."""
        conditions = []
        params: List[Any] = []

        if action:
            conditions.append("action = ?")
            params.append(action)
        if actor_id:
            conditions.append("actor_id = ?")
            params.append(actor_id)
        if org_id:
            conditions.append("org_id = ?")
            params.append(org_id)
        if result:
            conditions.append("result = ?")
            params.append(result)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.extend([limit, offset])

        rows = self._conn.execute(
            f"SELECT * FROM audit_log {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()

        return [
            {
                "log_id":     r["log_id"],
                "timestamp":  r["timestamp"],
                "action":     r["action"],
                "actor_id":   r["actor_id"],
                "actor_name": r["actor_name"],
                "org_id":     r["org_id"],
                "resource":   r["resource"],
                "result":     r["result"],
                "detail":     json.loads(r["detail"]) if r["detail"] else None,
                "ip_address": r["ip_address"],
            }
            for r in rows
        ]

    def count(self, *, action: Optional[str] = None, org_id: Optional[str] = None) -> int:
        conditions, params = [], []
        if action:
            conditions.append("action = ?"); params.append(action)
        if org_id:
            conditions.append("org_id = ?"); params.append(org_id)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        return self._conn.execute(f"SELECT COUNT(*) FROM audit_log {where}", params).fetchone()[0]

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_store: Optional[AuditLogStore] = None


def get_audit_store(db_path: Optional[Path] = None) -> AuditLogStore:
    global _store
    if _store is None:
        _store = AuditLogStore(db_path or _DEFAULT_DB_PATH)
    return _store


def reset_audit_store() -> None:
    global _store
    if _store is not None:
        try:
            _store.close()
        except Exception:
            pass
        _store = None


# ---------------------------------------------------------------------------
# Convenience action constants
# ---------------------------------------------------------------------------

class AuditAction:
    # Auth
    LOGIN           = "LOGIN"
    LOGIN_FAILED    = "LOGIN_FAILED"
    LOGOUT          = "LOGOUT"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    PASSWORD_RESET   = "PASSWORD_RESET"
    ACCOUNT_LOCKED   = "ACCOUNT_LOCKED"

    # Users
    USER_CREATED    = "USER_CREATED"
    USER_UPDATED    = "USER_UPDATED"
    USER_DISABLED   = "USER_DISABLED"

    # Org access
    ORG_ACCESS_GRANTED  = "ORG_ACCESS_GRANTED"
    ORG_ACCESS_REVOKED  = "ORG_ACCESS_REVOKED"

    # Agents
    AGENT_KEY_ISSUED  = "AGENT_KEY_ISSUED"
    AGENT_KEY_REVOKED = "AGENT_KEY_REVOKED"
    AGENT_REGISTERED  = "AGENT_REGISTERED"
    AGENT_REVOKED     = "AGENT_REVOKED"

    # Org config
    ORG_CONFIG_UPDATED = "ORG_CONFIG_UPDATED"

    # Maintenance
    BACKUP_CREATED = "BACKUP_CREATED"
    CHAIN_VERIFIED = "CHAIN_VERIFIED"

    # Evidence / violations
    VIOLATION_ACKNOWLEDGED = "VIOLATION_ACKNOWLEDGED"
    VIOLATION_RESOLVED     = "VIOLATION_RESOLVED"
    REPORT_EXPORTED        = "REPORT_EXPORTED"
    CHAIN_VERIFIED         = "CHAIN_VERIFIED"

    # System
    LICENSE_CHECKED = "LICENSE_CHECKED"
