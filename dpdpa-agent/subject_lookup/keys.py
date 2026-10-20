"""
Per-organization keys for the identifier index.

Two purposes, never mixed:
  lookup  the server's key. The index stores HMAC-SHA256(lookup key, normalised identifier) for identifiers the server
          sees in clear.
  agent   the key agents use in hash mode. The server hands it to the organization's agents over TLS at registration
          and at heartbeat, and needs it to look the same identifiers up again.

Every key has an id (a short hash of it, carried in the tokens it makes), so rotating never breaks old tokens: a lookup
tries every key that is not retired. Keys are 32 random bytes, encrypted at rest with the same key as the evidence
records, and are never part of an export. A backup contains them, because a backup contains the keys that read it.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, Optional, Tuple

import veritas_recognizers as vr
from db_encryption import decrypt_field, encrypt_field

PURPOSES = ("lookup", "agent")


def create_tables(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS org_keys (
            org TEXT NOT NULL, purpose TEXT NOT NULL, key_id TEXT NOT NULL, key_enc TEXT NOT NULL,
            created_at TEXT NOT NULL, retired_at TEXT,
            PRIMARY KEY (org, purpose, key_id))""")


class KeyRing:
    def __init__(self, store) -> None:
        self._store = store

    def _insert(self, conn, org: str, purpose: str) -> Tuple[str, bytes]:
        key = os.urandom(32)
        kid = vr.key_id_of(key)
        conn.execute("INSERT INTO org_keys (org, purpose, key_id, key_enc, created_at) VALUES (?, ?, ?, ?, ?)",
                     (org, purpose, kid, encrypt_field(key.hex()), datetime.now(timezone.utc).isoformat()))
        return kid, key

    def current(self, org: str, purpose: str) -> Tuple[str, bytes]:
        """The newest key that is not retired, made on first use."""
        assert purpose in PURPOSES
        with self._store.writer() as conn:
            row = conn.execute("SELECT key_id, key_enc FROM org_keys WHERE org = ? AND purpose = ? AND retired_at IS NULL "
                               "ORDER BY created_at DESC, rowid DESC LIMIT 1", (org, purpose)).fetchone()
            if row is None:
                return self._insert(conn, org, purpose)
            return row["key_id"], bytes.fromhex(decrypt_field(row["key_enc"]))

    def active(self, org: str, purpose: str) -> List[Tuple[str, bytes]]:
        """Every key a lookup must try (not retired), newest first. Empty if the organization has none yet."""
        with self._store._lock:
            rows = self._store._conn.execute(
                "SELECT key_id, key_enc FROM org_keys WHERE org = ? AND purpose = ? AND retired_at IS NULL "
                "ORDER BY created_at DESC, rowid DESC", (org, purpose)).fetchall()
        return [(r["key_id"], bytes.fromhex(decrypt_field(r["key_enc"]))) for r in rows]

    def rotate(self, org: str, purpose: str) -> str:
        """Make a new current key. The old one stays active, so tokens made under it are still found."""
        assert purpose in PURPOSES
        with self._store.writer() as conn:
            return self._insert(conn, org, purpose)[0]

    def retire(self, org: str, key_id: str) -> bool:
        """Stop trying a key (for example after a host that held it was compromised). Its tokens can no longer be found."""
        with self._store.writer() as conn:
            n = conn.execute("UPDATE org_keys SET retired_at = ? WHERE org = ? AND key_id = ? AND retired_at IS NULL",
                             (datetime.now(timezone.utc).isoformat(), org, key_id)).rowcount
        return n > 0

    def listing(self, org: str) -> List[dict]:
        """Ids, purposes and dates only; never key material."""
        with self._store._lock:
            rows = self._store._conn.execute(
                "SELECT purpose, key_id, created_at, retired_at FROM org_keys WHERE org = ? "
                "ORDER BY purpose, created_at, rowid", (org,)).fetchall()
        return [dict(r) for r in rows]

    def agent_key_payload(self, org: str) -> dict:
        """What a registering or heartbeating agent receives to use in hash mode."""
        kid, key = self.current(org, "agent")
        return {"key_id": kid, "key": key.hex()}
