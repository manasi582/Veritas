"""
Veritas Agent Store — SQLite persistence (Block 2)
===================================================
Two tables in agent_store/agents.db:

  registration_keys  — one-time keys issued to admins for Agent bootstrap.
                       Each key is stored as sha256(plaintext), never as
                       plaintext. Single-use and time-limited (30 minutes).

  agents             — registered Agent records. Auth tokens stored as
                       sha256(plaintext); plaintext returned exactly once at
                       registration and never stored. Revocation sets
                       status='REVOKED'; the row is kept for audit purposes.

DESIGN FOLLOWS evidence_store/store.py PATTERNS:
  - module-level singleton via get_agent_store() / reset_agent_store()
  - threading.Lock() guards every write (sufficient for single-process demo)
  - check_same_thread=False on sqlite3.connect()
  - _init_schema() is idempotent (CREATE TABLE IF NOT EXISTS)
  - defaults taken inside get_agent_store(), not at module load, for test isolation
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from agent_store.models import Agent, AgentStatus, RegistrationKey

logger = logging.getLogger("agent_store.store")

_KEY_TTL_MINUTES = 30
from runtime_paths import data_root as _data_root
_DEFAULT_DB_PATH = _data_root() / "agents.db"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _agent_id_from_uuid() -> str:
    """Generate a human-readable Agent ID like VERITAS-AGENT-7F82A1."""
    return "VERITAS-AGENT-" + uuid4().hex[:6].upper()


def _dt(value: Optional[str]) -> Optional[datetime]:
    """Parse ISO8601 string from SQLite into a timezone-aware datetime."""
    if value is None:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# AgentStore
# ---------------------------------------------------------------------------

class AgentStore:
    """
    SQLite-backed store for registration keys and Agent records.
    All writes are guarded by a threading.Lock. The database uses write-ahead logging (a commit
    costs one disk sync, not three, and readers do not wait for the writer).

    The per-agent events_received counter is kept in memory and written in batches (at most every
    EVENT_FLUSH_SECONDS, and always before anything reads it or the store closes): writing it on
    every event cost a disk sync per event and was the second biggest cost of taking an event. A
    crash can lose the last few seconds of this informational counter, never an event.
    """

    EVENT_FLUSH_SECONDS = 2.0

    def __init__(self, db_path: str | Path = _DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._pending_events: dict = {}
        self._last_flush = time.monotonic()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS registration_keys (
                    key_id      TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    key_hash    TEXT NOT NULL UNIQUE,
                    created_at  TEXT NOT NULL,
                    expires_at  TEXT NOT NULL,
                    used        INTEGER NOT NULL DEFAULT 0,
                    used_at     TEXT
                );

                CREATE TABLE IF NOT EXISTS agents (
                    agent_id            TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    token_hash          TEXT NOT NULL UNIQUE,
                    status              TEXT NOT NULL DEFAULT 'ACTIVE',
                    source_label        TEXT NOT NULL DEFAULT '',
                    created_at          TEXT NOT NULL,
                    last_heartbeat_at   TEXT,
                    events_received     INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_agents_org_id ON agents(org_id);
                CREATE INDEX IF NOT EXISTS idx_keys_org_id ON registration_keys(org_id);
            """)
            self._migrate_agent_health_columns()
            self._migrate_reusable_key_columns()
            self._conn.commit()

    def _migrate_agent_health_columns(self) -> None:
        """Add the health-report columns to databases created before they existed."""
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(agents)")}
        for column in ("agent_version", "health_json", "health_updated_at"):
            if column not in existing:
                self._conn.execute(f"ALTER TABLE agents ADD COLUMN {column} TEXT")

    def _migrate_reusable_key_columns(self) -> None:
        """Add reusable-key columns to databases created before they existed."""
        key_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(registration_keys)")}
        additions = {
            "max_uses":   "INTEGER NOT NULL DEFAULT 1",
            "uses":       "INTEGER NOT NULL DEFAULT 0",
            "revoked":    "INTEGER NOT NULL DEFAULT 0",
            "revoked_at": "TEXT",
            "label":      "TEXT NOT NULL DEFAULT ''",
            "created_by": "TEXT",
        }
        added_uses = False
        for column, ddl in additions.items():
            if column not in key_cols:
                self._conn.execute(f"ALTER TABLE registration_keys ADD COLUMN {column} {ddl}")
                added_uses = added_uses or column == "uses"
        if added_uses:
            # Keys consumed before this change were single-use: record that use.
            self._conn.execute("UPDATE registration_keys SET uses = 1 WHERE used = 1")
        agent_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(agents)")}
        if "key_id" not in agent_cols:
            self._conn.execute("ALTER TABLE agents ADD COLUMN key_id TEXT")

    # ------------------------------------------------------------------
    # Registration keys
    # ------------------------------------------------------------------

    def issue_key_detailed(
        self,
        org_id: str,
        *,
        max_uses: int = 1,
        ttl_minutes: Optional[int] = None,
        label: str = "",
        created_by: Optional[str] = None,
    ) -> tuple[str, RegistrationKey]:
        """
        Generate a registration key for org_id and return (plaintext, key record).
        Stores sha256(key) only; the plaintext is shown once to the admin.

        Default: single use, valid 30 minutes. A key with max_uses > 1 can enrol that
        many agents (for example one per Kubernetes node) until it expires or is revoked.
        """
        if max_uses < 1:
            raise ValueError("max_uses must be at least 1")
        plaintext = secrets.token_urlsafe(16)
        key_hash = _sha256(plaintext)
        key_id = str(uuid4())
        now = _now()
        ttl = _KEY_TTL_MINUTES if ttl_minutes is None else ttl_minutes
        expires = now + timedelta(minutes=ttl)

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO registration_keys
                    (key_id, org_id, key_hash, created_at, expires_at, used, used_at,
                     max_uses, uses, revoked, label, created_by)
                VALUES (?, ?, ?, ?, ?, 0, NULL, ?, 0, 0, ?, ?)
                """,
                (key_id, org_id, key_hash, now.isoformat(), expires.isoformat(),
                 max_uses, label, created_by),
            )
            self._conn.commit()

        logger.info("Issued registration key %s for org %r (max_uses=%d, expires %s)",
                    key_id, org_id, max_uses, expires.isoformat())
        return plaintext, RegistrationKey(
            key_id=key_id, org_id=org_id, created_at=now, expires_at=expires,
            max_uses=max_uses, label=label, created_by=created_by,
        )

    def issue_key(self, org_id: str) -> str:
        """Generate a single-use registration key (30 minutes). Returns the plaintext."""
        return self.issue_key_detailed(org_id)[0]

    def list_keys(self, org_id: str) -> List[RegistrationKey]:
        """All keys issued for an org, newest first (metadata only; plaintext is never stored)."""
        rows = self._conn.execute(
            "SELECT * FROM registration_keys WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
        return [_row_to_key(r) for r in rows]

    def get_key(self, key_id: str) -> Optional[RegistrationKey]:
        row = self._conn.execute(
            "SELECT * FROM registration_keys WHERE key_id = ?", (key_id,)
        ).fetchone()
        return _row_to_key(row) if row else None

    def revoke_key(self, key_id: str) -> bool:
        """Revoke a key so no further agents can enrol with it. Agents already enrolled keep working."""
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE registration_keys SET revoked = 1, revoked_at = ? "
                "WHERE key_id = ? AND revoked = 0",
                (_now().isoformat(), key_id),
            )
            self._conn.commit()
        found = cursor.rowcount > 0
        if found:
            logger.info("Revoked registration key %s", key_id)
        return found

    def consume_key(self, plaintext_key: str) -> RegistrationKey:
        """
        Validate a registration key and record one use of it.
        Raises ValueError if the key is unknown, revoked, expired or out of uses.
        The check and the increment happen together inside the write lock, so two
        agents racing for the last use cannot both succeed.
        """
        key_hash = _sha256(plaintext_key)

        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM registration_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()

            if row is None:
                raise ValueError("Registration key is invalid or does not exist.")

            key = _row_to_key(row)
            if key.revoked:
                raise ValueError("Registration key has been revoked.")

            if _now() > key.expires_at:
                raise ValueError(f"Registration key expired at {key.expires_at.isoformat()}.")

            if key.uses >= key.max_uses:
                if key.max_uses == 1:
                    raise ValueError("Registration key has already been used.")
                raise ValueError(
                    f"Registration key has reached its use limit ({key.max_uses} agents)."
                )

            uses = key.uses + 1
            self._conn.execute(
                "UPDATE registration_keys SET uses = ?, used = ?, used_at = ? WHERE key_id = ?",
                (uses, 1 if uses >= key.max_uses else 0, _now().isoformat(), key.key_id),
            )
            self._conn.commit()

        key.uses = uses
        key.used = uses >= key.max_uses
        return key

    # ------------------------------------------------------------------
    # Agent creation & lookup
    # ------------------------------------------------------------------

    def create_agent(
        self, org_id: str, source_label: str = "", key_id: Optional[str] = None
    ) -> tuple[Agent, str]:
        """
        Create a new Agent for org_id.
        Returns (Agent, plaintext_auth_token). The plaintext token is returned
        exactly once — it is NOT stored. Only sha256(token) is persisted.
        """
        plaintext_token = secrets.token_urlsafe(32)
        token_hash = _sha256(plaintext_token)
        agent_id = _agent_id_from_uuid()
        now = _now()

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO agents
                    (agent_id, org_id, token_hash, status, source_label,
                     created_at, last_heartbeat_at, events_received, key_id)
                VALUES (?, ?, ?, 'ACTIVE', ?, ?, NULL, 0, ?)
                """,
                (agent_id, org_id, token_hash, source_label, now.isoformat(), key_id),
            )
            self._conn.commit()

        agent = Agent(
            agent_id=agent_id,
            org_id=org_id,
            status=AgentStatus.ACTIVE,
            source_label=source_label,
            created_at=now,
        )
        logger.info("Created agent %s for org %r", agent_id, org_id)
        return agent, plaintext_token

    def validate_token(self, plaintext_token: str) -> Optional[Agent]:
        """
        Look up an Agent by its auth token.
        Returns the Agent (regardless of status — caller checks status).
        Returns None if the token doesn't match any agent.
        """
        token_hash = _sha256(plaintext_token)
        row = self._conn.execute(
            "SELECT * FROM agents WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()

        if row is None:
            return None

        return _row_to_agent(row)

    def get_agent(self, agent_id: str) -> Optional[Agent]:
        """Look up an Agent by its ID."""
        self.flush_events()
        row = self._conn.execute(
            "SELECT * FROM agents WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        return _row_to_agent(row) if row else None

    def list_agents(self, org_id: Optional[str] = None) -> List[Agent]:
        """List all agents, optionally filtered by org_id."""
        self.flush_events()
        if org_id is not None:
            rows = self._conn.execute(
                "SELECT * FROM agents WHERE org_id = ? ORDER BY created_at",
                (org_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM agents ORDER BY created_at"
            ).fetchall()
        return [_row_to_agent(r) for r in rows]

    # ------------------------------------------------------------------
    # Agent mutations
    # ------------------------------------------------------------------

    def revoke_agent(self, agent_id: str) -> bool:
        """
        Set agent status to REVOKED.
        Returns True if the agent was found and revoked, False if not found.
        """
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE agents SET status = 'REVOKED' WHERE agent_id = ?",
                (agent_id,),
            )
            self._conn.commit()

        found = cursor.rowcount > 0
        if found:
            logger.info("Revoked agent %s", agent_id)
        return found

    def record_heartbeat(self, agent_id: str, health: Optional[dict] = None) -> None:
        """
        Update last_heartbeat_at for an agent. If the agent sent a health report
        (version, queue, counters, per-source state), store it as well.
        """
        now = _now().isoformat()
        with self._lock:
            if health is None:
                self._conn.execute(
                    "UPDATE agents SET last_heartbeat_at = ? WHERE agent_id = ?",
                    (now, agent_id),
                )
            else:
                self._conn.execute(
                    "UPDATE agents SET last_heartbeat_at = ?, agent_version = ?, "
                    "health_json = ?, health_updated_at = ? WHERE agent_id = ?",
                    (now, health.get("agent_version") or None,
                     json.dumps(health, separators=(",", ":")), now, agent_id),
                )
            self._conn.commit()

    def increment_events(self, agent_id: str) -> None:
        """Count one accepted event for an agent (written to disk in batches, see the class note)."""
        with self._lock:
            self._pending_events[agent_id] = self._pending_events.get(agent_id, 0) + 1
            if time.monotonic() - self._last_flush >= self.EVENT_FLUSH_SECONDS:
                self._flush_events_locked()

    def flush_events(self) -> None:
        """Write the batched counters now."""
        with self._lock:
            self._flush_events_locked()

    def _flush_events_locked(self) -> None:
        self._last_flush = time.monotonic()
        if not self._pending_events:
            return
        pending, self._pending_events = self._pending_events, {}
        self._conn.executemany(
            "UPDATE agents SET events_received = events_received + ? WHERE agent_id = ?",
            [(n, agent_id) for agent_id, n in pending.items()],
        )
        self._conn.commit()

    def close(self) -> None:
        try:
            self.flush_events()
        finally:
            self._conn.close()


# ---------------------------------------------------------------------------
# Row → model helper
# ---------------------------------------------------------------------------

def _row_to_key(row: sqlite3.Row) -> RegistrationKey:
    keys = row.keys()
    max_uses = row["max_uses"] if "max_uses" in keys else 1
    uses = row["uses"] if "uses" in keys else int(row["used"])
    return RegistrationKey(
        key_id=row["key_id"],
        org_id=row["org_id"],
        created_at=_dt(row["created_at"]),
        expires_at=_dt(row["expires_at"]),
        used=bool(row["used"]),
        max_uses=max_uses,
        uses=uses,
        revoked=bool(row["revoked"]) if "revoked" in keys else False,
        label=(row["label"] or "") if "label" in keys else "",
        created_by=row["created_by"] if "created_by" in keys else None,
    )


def _row_to_agent(row: sqlite3.Row) -> Agent:
    keys = row.keys()
    health = None
    if "health_json" in keys and row["health_json"]:
        try:
            health = json.loads(row["health_json"])
        except ValueError:
            health = None
    return Agent(
        agent_id=row["agent_id"],
        org_id=row["org_id"],
        status=AgentStatus(row["status"]),
        source_label=row["source_label"],
        created_at=_dt(row["created_at"]),
        last_heartbeat_at=_dt(row["last_heartbeat_at"]),
        events_received=row["events_received"],
        agent_version=row["agent_version"] if "agent_version" in keys else None,
        health=health,
        health_updated_at=_dt(row["health_updated_at"]) if "health_updated_at" in keys else None,
    )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_store: Optional[AgentStore] = None


def get_agent_store(db_path: Optional[str | Path] = None) -> AgentStore:
    """
    Return the module-level AgentStore singleton, lazily initialised.
    db_path defaults are evaluated fresh on each call (not at import time)
    so tests can override with tmp_path before the first call.
    """
    global _store
    if _store is None:
        _store = AgentStore(db_path or _DEFAULT_DB_PATH)
    return _store


def reset_agent_store() -> None:
    """Close and discard the singleton. Used in tests for isolation."""
    global _store
    if _store is not None:
        try:
            _store.close()
        except Exception:
            pass
        _store = None
