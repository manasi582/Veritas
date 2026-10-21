"""
DPDPA Compliance Agent — Evidence Store (Phase 6, multi-tenant since Phase 5+6)
=================================================================================
Append-only, SHA-256 hash-chained SQLite store for ExplainedVerdict objects.

DESIGN DECISIONS (documented per the plan's requirement):

1. IMMUTABILITY + MUTABILITY SPLIT:
   `remediation_status` and `remediation_updated_at` live in SEPARATE COLUMNS
   outside the hashed payload. The hash covers everything else — the full
   ExplainedVerdict JSON serialised deterministically. Updating remediaton
   status NEVER changes the stored hash, so verify_chain() passes before and
   after a status update. This is the simplest correct option.

2. HASH CHAIN — NOW PER-TENANT (Phase 5+6 change):
   Each row stores sha256(json(immutable_fields) + previous_row_hash). Before
   this phase, "previous_row_hash" was the immediately preceding row GLOBALLY
   (SELECT ... ORDER BY row_index DESC LIMIT 1, no tenant filter) — meaning
   org A's rows and org B's rows were interleaved into ONE chain, so
   verifying org A's evidence required touching org B's rows too. That broke
   the tenant-isolation goal: an org's auditor could not verify their own
   evidence independent of another org's data (or its presence/absence).

   FIX: the "previous hash" a new row chains into is now the last row
   belonging to the SAME tenant_id (_get_last_hash(tenant_id) — see below),
   falling back to GENESIS_HASH if this is that tenant's first-ever row. Each
   org therefore has its own independent hash chain, embedded in the same
   physical table (still one SQLite file, one row_index sequence — rows from
   different tenants can be physically interleaved by insertion order — but
   logically chained only within their own tenant's row sequence).
   verify_chain(tenant_id) replays ONLY that tenant's rows, in row_index
   order, starting from GENESIS_HASH. This is a pure query/chaining-scope
   change — the hash algorithm, what fields get hashed, and the append-only
   property are all unchanged (explicit non-goal of this phase).

   MIGRATION NOTE: a `tenant_id` column did not previously exist. On an
   existing on-disk DB (created before this phase), `_init_schema()` adds it
   and backfills every existing row's tenant_id from its own payload_json
   (which has always carried `verdict.tenant_id`, per Phase 0's schema — see
   `_serialize_immutable` below). Existing rows' `row_hash`/`previous_hash`
   values are NOT recomputed (that would violate the append-only/tamper-
   evidence guarantee retroactively) — they keep whatever chain they were
   originally written with. In this codebase's actual history, every row
   written before this phase was retail_co's (Phase 5 is the first time a
   non-retail_co tenant's verdicts could ever reach this store), so the
   pre-existing chain is — and remains, unchanged — exactly retail_co's
   per-tenant chain; no discontinuity is introduced for the common case.

3. STATUS TRANSITIONS:
   Only OPEN→ACKNOWLEDGED and ACKNOWLEDGED→RESOLVED are permitted. Attempting
   to go backwards (e.g. RESOLVED→OPEN) or skip (OPEN→RESOLVED) is rejected
   with a ValueError. ACKNOWLEDGED→ACKNOWLEDGED is also explicitly rejected
   (idempotent updates aren't meaningful here).

4. SQLITE CONCURRENCY:
   check_same_thread=False + a module-level threading.Lock guard every write.
   Sufficient for the hackathon single-process model.

5. SCHEMA EVOLUTION:
   All immutable verdict fields + explanation fields are stored as a single
   JSON blob column (`payload_json`) for simplicity. The mutable fields are
   their own indexed columns so queries and updates touch only those.
   `tenant_id` is ALSO its own indexed column (denormalised out of
   payload_json) purely so every read path can filter/chain efficiently
   without parsing JSON per row.

6. TENANT SCOPING (Phase 5+6):
   Every read (and write-adjacent) method — append, verify_chain, query,
   get_by_verdict_id, update_status, count — now takes tenant_id as a
   REQUIRED parameter (append derives it from the verdict itself; the rest
   take it explicitly) and scopes its SQL accordingly. There is no "list
   across all tenants" method — that was a deliberate removal, not an
   oversight: any such method would be exactly the kind of cross-tenant leak
   surface this phase exists to close. A caller that genuinely needs a
   cross-tenant admin view would need a new, explicitly-named method — none
   of Part A/B's callers need one, so none was added.

7. PER-TENANT SEQUENTIAL VIOLATION ID (post-Phase-6 addition):
   Every stored row also gets a plain, human-referenceable `violation_id` —
   1, 2, 3, ... — SCOPED PER TENANT (org A's #1 and org B's #1 are
   different rows; each tenant's numbering starts fresh at 1). This is
   deliberately NOT the same thing as the existing `row_index`: row_index
   is a GLOBAL SQLite AUTOINCREMENT shared by every tenant's physically
   interleaved rows (e.g. org A's rows could sit at global positions
   1, 3, 5 if org B wrote in between), so it was never actually usable as
   "the Nth violation for this org" — an auditor filtering to their own
   org would see gaps. `violation_id` fixes that: it's computed as
   MAX(existing violation_id for this tenant) + 1 at append time, inside
   the same write lock, so it is gap-free and race-safe per tenant.

   It is deliberately NOT added to the Verdict schema (schemas/models.py)
   or assigned by the rule engine — a violation only earns a permanent
   audit-trail number once it is durably stored, which is exactly what
   this layer already owns. This keeps Verdict (frozen since Phase 0) and
   rules/engine.py untouched.

   Lookup: get_by_sequence_number(tenant_id, violation_id) — the
   "tag @03 and ask what happened" workflow. Since the explanation was
   already generated and grounding-checked once at detection time (see
   llm_explainer/explainer.py), this is a plain stored-row lookup, not a
   fresh LLM call — instant, and doesn't re-spend an API call per lookup.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from db_encryption import decrypt_field, encrypt_field
from evidence_store import canonical as cn
from evidence_store import flows as flows_mod
from evidence_store import incidents as inc
from notice_registry import coverage as notice_cov
from schema_watch import evaluate as schema_eval
from subject_lookup import index as subject_index, keys as subject_keys, rights as subject_rights
from rulebook import changes as rule_changes
from llm_explainer.explainer import ExplainedVerdict
from schemas.models import RemediationStatus

logger = logging.getLogger("evidence_store.store")

# The fixed genesis string hashed as the "previous hash" for the very first
# row OF EACH TENANT'S OWN CHAIN (see module docstring, point 2). The same
# literal genesis string is reused per-tenant (it is not itself
# tenant-specific data) — each tenant's chain independently starts here.
GENESIS_HASH = "DPDPA-AGENT-GENESIS-2026"

# Allowed remediation status transitions (source → allowed targets)
_VALID_TRANSITIONS: dict[str, list[str]] = {
    "OPEN": ["ACKNOWLEDGED"],
    "ACKNOWLEDGED": ["RESOLVED"],
    "RESOLVED": [],  # terminal state
}

from runtime_paths import data_root as _data_root
_DEFAULT_DB_PATH = _data_root() / "evidence.db"


def _serialize_immutable(ev: ExplainedVerdict) -> str:
    """
    Deterministic JSON serialization of the immutable portion of an
    ExplainedVerdict (everything except remediation_status and
    remediation_updated_at). This is what gets hashed.

    Uses sort_keys=True and no extra whitespace so the output is stable
    across Python versions and machine architectures. Uses `default=str`
    to handle datetime/UUID objects.
    """
    verdict = ev.verdict
    payload = {
        # Verdict immutable fields
        "tenant_id": verdict.tenant_id,
        "verdict_id": str(verdict.verdict_id),
        "event_id": str(verdict.event_id),
        "rule_id": verdict.rule_id.value,
        "severity": verdict.severity.value,
        "source": verdict.source.value,
        "source_system": verdict.source_system,
        "field": verdict.field,
        "timestamp": verdict.timestamp.isoformat(),
        "matched_registry_entry": verdict.matched_registry_entry,
        "breach_notification_candidate": verdict.breach_notification_candidate,
        # Explanation fields (also immutable post-write)
        "explanation": ev.explanation,
        "section_cited": ev.section_cited,
        "confidence": ev.confidence,
        "used_fallback": ev.used_fallback,
    }
    return json.dumps(payload, sort_keys=True, default=str)


def _compute_hash(payload_json: str, previous_hash: str) -> str:
    """sha256(payload_json + previous_hash) → hex digest."""
    content = payload_json + previous_hash
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class _Writer:
    """Context manager: holds the store's write lock, commits on success, rolls back on error."""
    def __init__(self, store):
        self._store = store

    def __enter__(self):
        self._store._lock.acquire()
        return self._store._conn

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._store._conn.commit()
            else:
                self._store._conn.rollback()
        finally:
            self._store._lock.release()
        return False


class EvidenceStore:
    """
    Append-only, hash-chained SQLite Evidence Store. Every chain, and every
    read, is scoped to a single tenant_id — see module docstring point 6.

    Public interface:
        append(ev: ExplainedVerdict) -> int (row_index, 0-based; tenant_id
            is read off ev.verdict.tenant_id, not passed separately)
        verify_chain(tenant_id: str) -> dict with {valid, first_broken_index}
        update_status(tenant_id: str, verdict_id: str, new_status: str) -> None
        query(tenant_id: str, ...) -> list[dict]
        get_by_verdict_id(tenant_id: str, verdict_id: str) -> Optional[dict]
        get_by_violation_id(tenant_id: str, violation_id: int) -> Optional[dict]
        count(tenant_id: str) -> int

    Thread-safe for single-process use via a write lock.
    """

    def __init__(self, db_path: str | Path = _DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # write-ahead logging: a commit costs one disk sync instead of three, and readers (the dashboard)
        # do not wait for the writer. A commit is still durable once it returns.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()
        self.flows = flows_mod.FlowCounter(self)
        self.keyring = subject_keys.KeyRing(self)
        self.subjects = subject_index.SubjectIndex(self)

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    row_index           INTEGER PRIMARY KEY AUTOINCREMENT,
                    verdict_id          TEXT NOT NULL UNIQUE,
                    payload_json        TEXT NOT NULL,
                    row_hash            TEXT NOT NULL,
                    previous_hash       TEXT NOT NULL,
                    remediation_status  TEXT NOT NULL DEFAULT 'OPEN',
                    remediation_updated_at TEXT,
                    appended_at         TEXT NOT NULL
                )
            """)
            self._migrate_add_tenant_id_column()
            self._migrate_add_violation_id_column()
            self._migrate_add_summary_columns()
            self._migrate_add_chain_columns()
            self._migrate_add_case_tables()
            inc.create_tables(self._conn)
            flows_mod.create_tables(self._conn)
            schema_eval.create_tables(self._conn)
            notice_cov.create_tables(self._conn)
            subject_keys.create_tables(self._conn)
            subject_index.create_tables(self._conn)
            subject_rights.create_tables(self._conn)
            rule_changes.create_tables(self._conn)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_verdict_id ON evidence(verdict_id)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_remediation_status ON evidence(remediation_status)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_source_system ON evidence(payload_json)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tenant_id ON evidence(tenant_id)"
            )
            self._conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_violation_id ON evidence(tenant_id, violation_id)"
            )
            self._conn.commit()

    def _migrate_add_tenant_id_column(self) -> None:
        """
        Phase 5+6 migration: add `tenant_id` if this DB predates it, and
        backfill existing rows from their own payload_json (which has always
        carried tenant_id — see _serialize_immutable). Does NOT touch
        row_hash/previous_hash — see module docstring point 2's migration
        note on why recomputing historical hashes would be wrong.
        Idempotent — safe to call on every startup.
        """
        existing_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(evidence)")}
        if "tenant_id" in existing_cols:
            return

        logger.info("Migrating evidence store: adding tenant_id column and backfilling from payload_json.")
        self._conn.execute("ALTER TABLE evidence ADD COLUMN tenant_id TEXT")
        rows = self._conn.execute("SELECT row_index, payload_json FROM evidence").fetchall()
        for row in rows:
            payload = json.loads(decrypt_field(row["payload_json"]))
            tenant_id = payload.get("tenant_id", "")
            self._conn.execute(
                "UPDATE evidence SET tenant_id = ? WHERE row_index = ?",
                (tenant_id, row["row_index"]),
            )
        if rows:
            logger.info("Backfilled tenant_id for %d existing row(s).", len(rows))

    def _migrate_add_violation_id_column(self) -> None:
        """
        Adds `violation_id` (per-tenant sequential number — see module
        docstring point 7) if this DB predates it, and backfills existing
        rows PER TENANT in row_index ASC order (i.e. insertion order),
        so the earliest row a tenant ever had becomes their #1, preserving
        real history rather than an arbitrary renumbering. Idempotent.
        """
        existing_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(evidence)")}
        if "violation_id" in existing_cols:
            return

        logger.info("Migrating evidence store: adding violation_id column (per-tenant sequential numbering).")
        self._conn.execute("ALTER TABLE evidence ADD COLUMN violation_id INTEGER")
        tenant_ids = [r["tenant_id"] for r in self._conn.execute(
            "SELECT DISTINCT tenant_id FROM evidence WHERE tenant_id IS NOT NULL"
        )]
        for tid in tenant_ids:
            rows = self._conn.execute(
                "SELECT row_index FROM evidence WHERE tenant_id = ? ORDER BY row_index ASC", (tid,)
            ).fetchall()
            for n, row in enumerate(rows, start=1):
                self._conn.execute(
                    "UPDATE evidence SET violation_id = ? WHERE row_index = ?", (n, row["row_index"])
                )
        if tenant_ids:
            logger.info("Backfilled violation_id for %d tenant(s).", len(tenant_ids))

    _SUMMARY_COLUMNS = (("rule_id", "TEXT"), ("severity", "TEXT"), ("source_system", "TEXT"),
                        ("breach_candidate", "INTEGER"))

    def _migrate_add_summary_columns(self) -> None:
        """
        Adds rule_id, severity, source_system and breach_candidate as plain columns, copied from the
        record when it is written, so the dashboard's overview can be counted by the database instead
        of by decrypting every record. They are NOT part of the hash; verify_chain() checks each one
        against the signed record, so a changed column is reported like any other tampering.
        Existing rows are filled once, here. Idempotent.
        """
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(evidence)")}
        for name, kind in self._SUMMARY_COLUMNS:
            if name not in existing:
                self._conn.execute(f"ALTER TABLE evidence ADD COLUMN {name} {kind}")
        todo = self._conn.execute("SELECT row_index, payload_json FROM evidence WHERE rule_id IS NULL").fetchall()
        if not todo:
            return
        logger.info("Migrating evidence store: filling summary columns for %d existing row(s).", len(todo))
        for n, row in enumerate(todo, start=1):
            p = json.loads(decrypt_field(row["payload_json"]))
            self._conn.execute(
                "UPDATE evidence SET rule_id = ?, severity = ?, source_system = ?, breach_candidate = ? "
                "WHERE row_index = ?",
                (p.get("rule_id"), p.get("severity"), p.get("source_system"),
                 1 if p.get("breach_notification_candidate") else 0, row["row_index"]))
            if n % 2000 == 0:
                self._conn.commit()
        self._conn.commit()

    def _migrate_add_chain_columns(self) -> None:
        """
        Foundation for hash_version 1 (see evidence_store/canonical.py). Adds, to a database that predates it:
          seq              position in the organization's chain (1, 2, 3, ...), filled for existing rows
          record_type      VERDICT, or an event (STATUS_CHANGE, COMMENT) chained in the same sequence
          hash_version     0 for every existing row (never rehashed), 1 for rows written from now on
          status_baseline  a verdict's status when it was written (existing rows: their current status)
          target_id        the verdict an event is about
        Takes a private copy of the database first when there is anything to migrate. Idempotent.
        """
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)
        """)
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(evidence)")}
        if "seq" not in existing:
            n = self._conn.execute("SELECT COUNT(*) AS n FROM evidence").fetchone()["n"]
            if n:
                self._backup_before_migration()
            logger.info("Migrating evidence store: chain columns (hash_version 1 foundation), %d existing row(s).", n)
            self._conn.execute("ALTER TABLE evidence ADD COLUMN seq INTEGER")
            self._conn.execute("ALTER TABLE evidence ADD COLUMN record_type TEXT NOT NULL DEFAULT 'VERDICT'")
            self._conn.execute("ALTER TABLE evidence ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 0")
            self._conn.execute("ALTER TABLE evidence ADD COLUMN status_baseline TEXT NOT NULL DEFAULT 'OPEN'")
            self._conn.execute("ALTER TABLE evidence ADD COLUMN target_id TEXT")
            self._conn.execute("UPDATE evidence SET status_baseline = remediation_status")
            for t in [r["tenant_id"] for r in self._conn.execute("SELECT DISTINCT tenant_id FROM evidence")]:
                rows = self._conn.execute(
                    "SELECT row_index FROM evidence WHERE tenant_id IS ? ORDER BY row_index ASC", (t,)).fetchall()
                for n_, row in enumerate(rows, start=1):
                    self._conn.execute("UPDATE evidence SET seq = ? WHERE row_index = ?", (n_, row["row_index"]))
        self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_seq ON evidence(tenant_id, seq)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tenant_target ON evidence(tenant_id, target_id)")
        if not self._conn.execute("SELECT 1 FROM schema_version WHERE version = 2").fetchone():
            self._conn.execute(
                "INSERT INTO schema_version (version, name, applied_at) VALUES (2, 'chain columns, hash_version 1', ?)",
                (datetime.now(timezone.utc).isoformat(),))
        self._conn.commit()

    def _backup_before_migration(self) -> None:
        """A private, consistent copy of the database next to it, made before a format migration."""
        try:
            self._conn.commit()
            target_dir = self.db_path.parent / "backups"
            target_dir.mkdir(parents=True, exist_ok=True)
            dest = target_dir / f"evidence-before-migration-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.db"
            out = sqlite3.connect(str(dest))
            try:
                self._conn.backup(out)
            finally:
                out.close()
            try:
                dest.chmod(0o600)
            except OSError:
                pass
            logger.info("Copy of the evidence database before migration: %s", dest)
        except Exception as e:   # a missing copy must be loud, but must not stop the server from starting
            logger.error("Could not make a copy of the evidence database before migration: %s", e)

    def _migrate_add_case_tables(self) -> None:
        """Phase 13 migration: add case_metadata and case_comments tables."""
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS case_metadata (
                verdict_id   TEXT PRIMARY KEY,
                tenant_id    TEXT NOT NULL,
                assignee     TEXT,
                priority     TEXT DEFAULT 'MEDIUM',
                due_date     TEXT,
                notes        TEXT,
                updated_at   TEXT NOT NULL,
                updated_by   TEXT
            );

            CREATE TABLE IF NOT EXISTS case_comments (
                comment_id   TEXT PRIMARY KEY,
                verdict_id   TEXT NOT NULL,
                tenant_id    TEXT NOT NULL,
                author_id    TEXT,
                author_name  TEXT,
                content      TEXT NOT NULL,
                created_at   TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_case_verdict   ON case_metadata(verdict_id);
            CREATE INDEX IF NOT EXISTS idx_case_tenant    ON case_metadata(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_comments_verdict ON case_comments(verdict_id);
        """)
        self._conn.commit()

    def _get_next_violation_id(self, tenant_id: str) -> int:
        """Next per-tenant sequential number: MAX(existing)+1, or 1 if this
        tenant has no rows yet. Called inside the write lock in append()."""
        cursor = self._conn.execute(
            "SELECT MAX(violation_id) as m FROM evidence WHERE tenant_id = ?", (tenant_id,)
        )
        current_max = cursor.fetchone()["m"]
        return (current_max or 0) + 1

    def _get_last_hash(self, tenant_id: str) -> str:
        """Returns this tenant's last row's hash, or GENESIS_HASH if this
        tenant has no rows yet — the per-tenant chain start point."""
        cursor = self._conn.execute(
            "SELECT row_hash FROM evidence WHERE tenant_id = ? ORDER BY row_index DESC LIMIT 1",
            (tenant_id,),
        )
        row = cursor.fetchone()
        return row["row_hash"] if row else GENESIS_HASH

    def tenants(self) -> List[str]:
        """Every organization that has at least one record (used by the anchoring scheduler)."""
        return [r["tenant_id"] for r in self._conn.execute(
            "SELECT DISTINCT tenant_id FROM evidence WHERE tenant_id IS NOT NULL AND tenant_id != '' ORDER BY tenant_id")]

    def chain_head(self, tenant_id: str) -> dict:
        """{"last_seq", "head_hash", "record_count"} of the organization's chain (all record types)."""
        row = self._conn.execute(
            "SELECT seq, row_hash FROM evidence WHERE tenant_id = ? ORDER BY row_index DESC LIMIT 1", (tenant_id,)).fetchone()
        n = self._conn.execute("SELECT COUNT(*) AS n FROM evidence WHERE tenant_id = ?", (tenant_id,)).fetchone()["n"]
        return {"last_seq": row["seq"] if row else 0, "head_hash": row["row_hash"] if row else None, "record_count": n}

    def export_records(self, tenant_id: str):
        """
        Yield every record of the organization's chain in order, as the stand-alone verifier reads them. Uses
        its own read-only connection so a long export never holds up the writer.
        A version 0 record carries the exact stored text (`payload_json`); a version 1 record carries its
        canonical `body` (see evidence_store/canonical.py).
        """
        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(
                "SELECT seq, record_type, hash_version, previous_hash, row_hash, payload_json "
                "FROM evidence WHERE tenant_id = ? ORDER BY row_index ASC", (tenant_id,))
            for row in cur:
                text = decrypt_field(row["payload_json"])
                rec = {"seq": row["seq"], "record_type": row["record_type"], "hash_version": row["hash_version"],
                       "prev": row["previous_hash"], "hash": row["row_hash"]}
                if row["hash_version"] == 0:
                    rec["payload_json"] = text
                else:
                    rec["body"] = json.loads(text)
                yield rec
        finally:
            conn.close()

    def writer(self):
        """The store's lock and connection, for modules that add their own tables (anchoring). Use: with store.writer() as conn."""
        return _Writer(self)

    def _get_last_seq(self, tenant_id: str) -> int:
        row = self._conn.execute("SELECT MAX(seq) AS m FROM evidence WHERE tenant_id = ?", (tenant_id,)).fetchone()
        return row["m"] or 0

    @staticmethod
    def _decode(row) -> dict:
        """A stored record's content in the shape the rest of the product reads (version 0 field names)."""
        payload = json.loads(decrypt_field(row["payload_json"]))
        return cn.legacy_view(payload) if row["hash_version"] == 1 else payload

    def _append_event(self, tenant_id: str, record_type: str, target: str, body_fn) -> str:
        """Chain one event record (status change or comment). Caller holds the lock and commits."""
        event_id = str(uuid.uuid4())
        seq = self._get_last_seq(tenant_id) + 1
        previous_hash = self._get_last_hash(tenant_id)
        body = body_fn(event_id, seq)
        row_hash = cn.v1_hash(previous_hash, body)
        self._conn.execute("""
            INSERT INTO evidence (verdict_id, payload_json, row_hash, previous_hash, remediation_status,
                                  appended_at, tenant_id, seq, record_type, hash_version, target_id)
            VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, 1, ?)
        """, (event_id, encrypt_field(cn.canonical_json(body)), row_hash, previous_hash,
              datetime.now(timezone.utc).isoformat(), tenant_id, seq, record_type, target))
        return event_id

    def append(self, ev: ExplainedVerdict, grouping=None) -> int:
        """
        Append an ExplainedVerdict to the store. tenant_id is read from
        ev.verdict.tenant_id (never passed separately — there is exactly one
        source of truth for which tenant a verdict belongs to: the verdict
        itself). Chains into that tenant's own previous row (or GENESIS_HASH
        if this is their first). Returns the 0-based row_index of the new row.
        Raises sqlite3.IntegrityError if verdict_id already exists (duplicate).

        `grouping` is (template, hint) of the log line (incidents/template.py): the verdict is then attached to its
        incident in the same transaction. A failure of the grouping never loses the verdict (it is grouped later by
        backfill_incidents).
        """
        tenant_id = ev.verdict.tenant_id
        with self._lock:
            previous_hash = self._get_last_hash(tenant_id)
            violation_id = self._get_next_violation_id(tenant_id)
            seq = self._get_last_seq(tenant_id) + 1
            body = cn.verdict_body(ev, tenant_id, seq)
            payload_json = cn.canonical_json(body)
            row_hash = cn.v1_hash(previous_hash, body)           # hash_version 1 (canonical_json, see canonical.py)
            appended_at = datetime.now(timezone.utc).isoformat()
            status = ev.verdict.remediation_status.value

            self._conn.execute("""
                INSERT INTO evidence
                    (verdict_id, payload_json, row_hash, previous_hash,
                     remediation_status, remediation_updated_at, appended_at, tenant_id, violation_id,
                     rule_id, severity, source_system, breach_candidate,
                     seq, record_type, hash_version, status_baseline)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'VERDICT', 1, ?)
            """, (
                str(ev.verdict.verdict_id),
                encrypt_field(payload_json),   # store encrypted; hash was computed on plaintext
                row_hash,
                previous_hash,
                ev.verdict.remediation_status.value,
                ev.verdict.remediation_updated_at.isoformat() if ev.verdict.remediation_updated_at else None,
                appended_at,
                tenant_id,
                violation_id,
                ev.verdict.rule_id.value,
                ev.verdict.severity.value,
                ev.verdict.source_system,
                1 if ev.verdict.breach_notification_candidate else 0,
                seq,
                status,
            ))
            if inc.enabled():
                v = ev.verdict
                self._conn.execute("SAVEPOINT grouping")
                try:
                    inc.attach(self, tenant_id, str(v.verdict_id), v.rule_id.value, v.severity.value,
                               v.source_system, v.field, bool(v.breach_notification_candidate),
                               grouping[0] if grouping else inc.LEGACY_TEMPLATE, grouping[1] if grouping else None)
                    self._conn.execute("RELEASE grouping")
                except Exception:
                    logger.warning("grouping failed for verdict %s; it is stored and will be grouped later",
                                   v.verdict_id, exc_info=True)
                    self._conn.execute("ROLLBACK TO grouping")
                    self._conn.execute("RELEASE grouping")
            self._conn.commit()

            cursor = self._conn.execute(
                "SELECT row_index FROM evidence WHERE verdict_id = ?",
                (str(ev.verdict.verdict_id),)
            )
            return cursor.fetchone()["row_index"] - 1  # convert to 0-based

    def verify_chain(self, tenant_id: str) -> dict:
        """
        Recompute THIS TENANT's own chain and compare it with what is stored. Never touches another tenant's rows
        (an organization can verify its own evidence without trusting or needing anyone else's).

        Returns {"valid": True, "first_broken_index": None} for a sound chain, or
        {"valid": False, "first_broken_index": N}: N is 0-based within this tenant's own record sequence.
        verify_chain_detail() also says what was wrong.
        """
        detail = self.verify_chain_detail(tenant_id)
        return {"valid": detail["valid"], "first_broken_index": detail["first_broken_index"]}

    def verify_chain_detail(self, tenant_id: str) -> dict:
        """
        Checks, in order, for every record of the tenant:
          * the record hash (version 0: sha256(payload + previous); version 1: canonical body, see canonical.py);
          * the link to the previous record, and that `seq` counts 1, 2, 3 ... without a gap;
          * for a verdict, that the plain summary columns agree with the signed record;
          * for an event, that it is about a verdict of this tenant and the status change is a valid step.
        At the end, each verdict's cached status must equal its baseline plus its status-change events.
        Returns {"valid", "first_broken_index", "reason", "records", "head_hash"}.
        """
        rows = self._conn.execute(
            "SELECT row_index, payload_json, row_hash, previous_hash, rule_id, severity, source_system, "
            "breach_candidate, seq, record_type, hash_version, status_baseline, verdict_id, target_id, "
            "remediation_status FROM evidence WHERE tenant_id = ? ORDER BY row_index ASC",
            (tenant_id,),
        ).fetchall()

        def bad(i: int, reason: str, global_index: int) -> dict:
            logger.warning("Chain broken for tenant_id=%r at tenant-local index %d (global row_index=%d): %s",
                           tenant_id, i, global_index, reason)
            return {"valid": False, "first_broken_index": i, "reason": reason, "records": len(rows), "head_hash": None}

        expected_previous = GENESIS_HASH
        status = {}           # verdict_id -> replayed status
        cached = {}           # verdict_id -> (cached status, index)
        incident_status = {}  # incident_id -> replayed status
        rights_state = {}     # request_id -> replayed {status, tasks}
        rule_state = {}       # change_id -> replayed {status, kind, proposer}
        for i, row in enumerate(rows):
            plaintext_json = decrypt_field(row["payload_json"])
            signed = json.loads(plaintext_json)
            if row["hash_version"] == 0:
                expected_hash = cn.v0_hash(plaintext_json, expected_previous)
            else:
                try:
                    expected_hash = cn.v1_hash(expected_previous, signed)
                except TypeError:
                    return bad(i, "HASH_MISMATCH", row["row_index"])
            if expected_hash != row["row_hash"]:
                return bad(i, "HASH_MISMATCH", row["row_index"])
            if row["previous_hash"] != expected_previous:
                return bad(i, "CHAIN_BREAK", row["row_index"])
            if row["seq"] != i + 1 or (row["hash_version"] == 1 and (signed.get("seq") != i + 1
                                                                      or signed.get("org") != tenant_id)):
                return bad(i, "CHAIN_BREAK", row["row_index"])

            rtype = row["record_type"]
            if rtype == cn.VERDICT:
                if row["hash_version"] == 1:
                    sc = (signed.get("rule_id"), signed.get("severity"), signed.get("source_system"),
                          1 if signed.get("breach_notification_candidate") else 0)
                else:
                    sc = (signed.get("rule_id"), signed.get("severity"), signed.get("source_system"),
                          1 if signed.get("breach_notification_candidate") else 0)
                if (row["rule_id"], row["severity"], row["source_system"], row["breach_candidate"]) != sc:
                    return bad(i, "SUMMARY_MISMATCH", row["row_index"])
                status[row["verdict_id"]] = row["status_baseline"]
                cached[row["verdict_id"]] = (row["remediation_status"], i)
            elif rtype == cn.STATUS_CHANGE:
                target = signed.get("target")
                if target not in status or signed.get("old_status") != status[target]:
                    return bad(i, "EVENT_INVALID", row["row_index"])
                if signed.get("new_status") not in _VALID_TRANSITIONS.get(status[target], []):
                    return bad(i, "EVENT_INVALID", row["row_index"])
                status[target] = signed["new_status"]
            elif rtype == cn.COMMENT:
                if signed.get("target") not in status:
                    return bad(i, "EVENT_INVALID", row["row_index"])
            elif rtype == cn.INCIDENT_EVENT:
                if row["hash_version"] != 1 or not inc.verify_event(signed, incident_status):
                    return bad(i, "EVENT_INVALID", row["row_index"])
            elif rtype == cn.RIGHTS_EVENT:
                if row["hash_version"] != 1 or not subject_rights.verify_event(signed, rights_state):
                    return bad(i, "EVENT_INVALID", row["row_index"])
            elif rtype == cn.RULE_EVENT:
                if row["hash_version"] != 1 or not rule_changes.verify_event(signed, rule_state):
                    return bad(i, "EVENT_INVALID", row["row_index"])
            elif rtype == cn.RESTORE_EVENT:
                if row["hash_version"] != 1 or signed.get("org") != tenant_id or not isinstance(signed.get("restored_away"), list):
                    return bad(i, "EVENT_INVALID", row["row_index"])
            else:
                return bad(i, "EVENT_INVALID", row["row_index"])
            expected_previous = row["row_hash"]

        for vid, (cache_value, idx) in cached.items():
            if status.get(vid) != cache_value:
                return bad(idx, "STATUS_CACHE_MISMATCH", rows[idx]["row_index"])
        for r in self._conn.execute("SELECT incident_id, status FROM incidents WHERE tenant_id = ?", (tenant_id,)):
            if incident_status.get(r["incident_id"], "OPEN") != r["status"]:
                return bad(len(rows) - 1, "STATUS_CACHE_MISMATCH", rows[-1]["row_index"])
        for r in self._conn.execute("SELECT request_id, status FROM rights_requests WHERE org = ?", (tenant_id,)):
            replayed = rights_state.get(r["request_id"])
            if replayed is None or replayed["status"] != r["status"]:
                return bad(len(rows) - 1, "STATUS_CACHE_MISMATCH", rows[-1]["row_index"])
            for t in self._conn.execute("SELECT system, status FROM request_tasks WHERE request_id = ?", (r["request_id"],)):
                if (replayed["tasks"] or {}).get(t["system"]) is not (t["status"] == "CONFIRMED"):
                    return bad(len(rows) - 1, "STATUS_CACHE_MISMATCH", rows[-1]["row_index"])
        for r in self._conn.execute("SELECT change_id, status FROM rule_changes WHERE org = ?", (tenant_id,)):
            replayed = rule_state.get(r["change_id"])
            if replayed is None or replayed["status"] != r["status"]:
                return bad(len(rows) - 1, "STATUS_CACHE_MISMATCH", rows[-1]["row_index"])
        return {"valid": True, "first_broken_index": None, "reason": None, "records": len(rows),
                "head_hash": expected_previous if rows else None}

    def update_status(self, tenant_id: str, verdict_id: str, new_status: str,
                      actor: str = "system", reason: Optional[str] = None) -> None:
        """
        Change a verdict's remediation status. The change is first chained as a STATUS_CHANGE event (who, when,
        from what to what, why), then the cached `remediation_status` column is updated, in one transaction. A
        status can therefore never change silently: verify_chain() replays the events and compares the result
        with the cache.

        A verdict_id of another tenant is treated exactly like one that does not exist.
        Only valid transitions: OPEN → ACKNOWLEDGED → RESOLVED.

        Raises ValueError for an unknown verdict or a transition that is not allowed.
        """
        new_status = new_status.upper()
        if new_status not in ("OPEN", "ACKNOWLEDGED", "RESOLVED"):
            raise ValueError(f"Invalid status: {new_status!r}")

        with self._lock:
            row = self._conn.execute(
                "SELECT remediation_status FROM evidence WHERE verdict_id = ? AND tenant_id = ? "
                "AND record_type = 'VERDICT'", (verdict_id, tenant_id)).fetchone()
            if row is None:
                raise ValueError(f"Verdict not found: {verdict_id!r}")

            current = row["remediation_status"]
            allowed = _VALID_TRANSITIONS.get(current, [])
            if new_status not in allowed:
                raise ValueError(
                    f"Invalid status transition: {current!r} → {new_status!r}. "
                    f"Allowed: {allowed}"
                )

            at = datetime.now(timezone.utc)
            try:
                self._append_event(
                    tenant_id, cn.STATUS_CHANGE, verdict_id,
                    lambda event_id, seq: cn.status_change_body(
                        tenant_id, seq, event_id, verdict_id, current, new_status, actor or "system", reason, at))
                self._conn.execute(
                    "UPDATE evidence SET remediation_status = ?, remediation_updated_at = ? "
                    "WHERE verdict_id = ? AND tenant_id = ? AND record_type = 'VERDICT'",
                    (new_status, at.isoformat(), verdict_id, tenant_id))
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            logger.info("Updated verdict %s (tenant_id=%r) status: %s → %s by %s",
                        verdict_id, tenant_id, current, new_status, actor)

    def query(
        self,
        tenant_id: str,
        date_range: tuple[str, str] | None = None,
        source_system: str | None = None,
        severity: str | None = None,
        remediation_status: str | None = None,
    ) -> list[dict]:
        """
        Query the evidence store, scoped to tenant_id. All other filters are
        optional and ANDed together.

        date_range: (start_iso, end_iso) inclusive strings filtering on the
                    verdict's timestamp (parsed from payload_json).
        source_system: filter on source_system value in payload_json.
        severity: filter on severity value in payload_json.
        remediation_status: filter on the mutable remediation_status column.

        Returns a list of dicts with all stored fields + parsed payload_json fields.
        """
        where_clauses = ["tenant_id = ?", "record_type = 'VERDICT'"]
        params: list = [tenant_id]

        if remediation_status:
            where_clauses.append("remediation_status = ?")
            params.append(remediation_status.upper())

        base_sql = "SELECT * FROM evidence WHERE " + " AND ".join(where_clauses)
        base_sql += " ORDER BY row_index ASC"

        cursor = self._conn.execute(base_sql, params)
        rows = cursor.fetchall()

        results = []
        for row in rows:
            payload = self._decode(row)

            # Apply payload-level filters (can't use SQL efficiently on JSON blob)
            if source_system and payload.get("source_system") != source_system:
                continue
            if severity and payload.get("severity") != severity.upper():
                continue
            if date_range:
                ts = payload.get("timestamp", "")
                start, end = date_range
                if not (start <= ts <= end + "z"):  # ISO string comparison works lexicographically
                    continue

            result = {
                "violation_id": row["violation_id"],
                "row_index": row["row_index"] - 1,  # 0-based
                "row_hash": row["row_hash"],
                "appended_at": row["appended_at"],
                "remediation_status": row["remediation_status"],
                "remediation_updated_at": row["remediation_updated_at"],
                **payload,
            }
            results.append(result)

        return results

    def get_by_verdict_id(self, tenant_id: str, verdict_id: str) -> Optional[dict]:
        """Return a single row by verdict_id, scoped to tenant_id. Returns
        None both when the verdict_id doesn't exist AND when it exists but
        belongs to a different tenant — same non-distinguishing behavior as
        update_status, for the same reason."""
        cursor = self._conn.execute(
            "SELECT * FROM evidence WHERE verdict_id = ? AND tenant_id = ? AND record_type = 'VERDICT'", (verdict_id, tenant_id)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        payload = self._decode(row)
        return {
            "violation_id": row["violation_id"],
            "row_index": row["row_index"] - 1,
            "row_hash": row["row_hash"],
            "appended_at": row["appended_at"],
            "remediation_status": row["remediation_status"],
            "remediation_updated_at": row["remediation_updated_at"],
            **payload,
        }

    def get_by_violation_id(self, tenant_id: str, violation_id: int) -> Optional[dict]:
        """
        Return a single row by its per-tenant sequential violation_id
        (the "@03" lookup) — scoped to tenant_id, same non-distinguishing
        None-on-miss behavior as get_by_verdict_id. This is the primary
        entry point for "tag #N and ask what the breach is": the returned
        dict already carries the stored `explanation`/`section_cited`
        (generated once, grounding-checked, at detection time — see
        llm_explainer/explainer.py), so no new LLM call happens here.
        """
        cursor = self._conn.execute(
            "SELECT * FROM evidence WHERE tenant_id = ? AND violation_id = ? AND record_type = 'VERDICT'", (tenant_id, violation_id)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        payload = self._decode(row)
        return {
            "violation_id": row["violation_id"],
            "row_index": row["row_index"] - 1,
            "row_hash": row["row_hash"],
            "appended_at": row["appended_at"],
            "remediation_status": row["remediation_status"],
            "remediation_updated_at": row["remediation_updated_at"],
            **payload,
        }

    def count(self, tenant_id: str) -> int:
        """Return total number of rows in the store for tenant_id."""
        cursor = self._conn.execute("SELECT COUNT(*) as n FROM evidence WHERE tenant_id = ? AND record_type = 'VERDICT'", (tenant_id,))
        return cursor.fetchone()["n"]

    def stats(self, tenant_id: str) -> dict:
        """
        The dashboard overview for one organization, counted by the database (no record is decrypted):
        {"total", "by_rule", "by_severity", "by_source_system", "by_status", "breach_candidates"}.
        """
        def grouped(column: str) -> dict:
            rows = self._conn.execute(
                f"SELECT {column} AS k, COUNT(*) AS n FROM evidence WHERE tenant_id = ? AND record_type = 'VERDICT' GROUP BY {column}",
                (tenant_id,)).fetchall()
            return {(r["k"] if r["k"] is not None else "unknown"): r["n"] for r in rows}

        by_status = grouped("remediation_status")
        breaches = self._conn.execute(
            "SELECT COUNT(*) AS n FROM evidence WHERE tenant_id = ? AND record_type = 'VERDICT' AND breach_candidate = 1", (tenant_id,)
        ).fetchone()["n"]
        return {"total": sum(by_status.values()), "by_rule": grouped("rule_id"),
                "by_severity": grouped("severity"), "by_source_system": grouped("source_system"),
                "by_status": by_status, "breach_candidates": breaches}

    def count_by_status(self, tenant_id: str) -> dict:
        """{remediation_status: number of findings} for tenant_id (cheap: no payload is read)."""
        rows = self._conn.execute(
            "SELECT remediation_status AS s, COUNT(*) AS n FROM evidence WHERE tenant_id = ? AND record_type = 'VERDICT' GROUP BY remediation_status",
            (tenant_id,)).fetchall()
        return {r["s"]: r["n"] for r in rows}

    # ------------------------------------------------------------------
    # Case Management (Phase 13)
    # ------------------------------------------------------------------

    def get_case(self, tenant_id: str, verdict_id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM case_metadata WHERE verdict_id = ? AND tenant_id = ?",
            (verdict_id, tenant_id),
        ).fetchone()
        return dict(row) if row else None

    def upsert_case(self, tenant_id: str, verdict_id: str, *, assignee=None,
                    priority=None, due_date=None, notes=None, updated_by=None) -> dict:
        """Create or update case metadata for a violation."""
        import datetime as _dt
        now = _dt.datetime.now(_dt.timezone.utc).isoformat()
        existing = self.get_case(tenant_id, verdict_id)
        if existing:
            updates, params = [], []
            for col, val in [("assignee", assignee), ("priority", priority),
                              ("due_date", due_date), ("notes", notes)]:
                if val is not None:
                    updates.append(f"{col} = ?"); params.append(val)
            updates += ["updated_at = ?", "updated_by = ?"]
            params += [now, updated_by, verdict_id, tenant_id]
            with self._lock:
                self._conn.execute(
                    f"UPDATE case_metadata SET {', '.join(updates)} WHERE verdict_id = ? AND tenant_id = ?",
                    params)
                self._conn.commit()
        else:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO case_metadata (verdict_id,tenant_id,assignee,priority,due_date,notes,updated_at,updated_by) VALUES (?,?,?,?,?,?,?,?)",
                    (verdict_id, tenant_id, assignee, priority or "MEDIUM", due_date, notes, now, updated_by))
                self._conn.commit()
        return self.get_case(tenant_id, verdict_id) or {}

    def add_comment(self, tenant_id: str, verdict_id: str, content: str,
                    author_id=None, author_name=None) -> dict:
        import datetime as _dt
        from uuid import uuid4 as _u4
        cid = str(_u4())
        now = _dt.datetime.now(_dt.timezone.utc).isoformat()
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO case_comments (comment_id,verdict_id,tenant_id,author_id,author_name,content,created_at) VALUES (?,?,?,?,?,?,?)",
                    (cid, verdict_id, tenant_id, author_id, author_name, content, now))
                if self._conn.execute("SELECT 1 FROM evidence WHERE verdict_id = ? AND tenant_id = ? AND record_type = 'VERDICT'",
                                      (verdict_id, tenant_id)).fetchone():
                    at = _dt.datetime.now(_dt.timezone.utc)
                    self._append_event(
                        tenant_id, cn.COMMENT, verdict_id,
                        lambda event_id, seq: cn.comment_body(tenant_id, seq, event_id, verdict_id,
                                                              author_name or author_id or "unknown", content, at))
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return {"comment_id": cid, "verdict_id": verdict_id, "author_id": author_id,
                "author_name": author_name, "content": content, "created_at": now}

    def get_comments(self, tenant_id: str, verdict_id: str) -> list:
        rows = self._conn.execute(
            "SELECT * FROM case_comments WHERE verdict_id = ? AND tenant_id = ? ORDER BY created_at DESC",
            (verdict_id, tenant_id)).fetchall()
        return [dict(r) for r in rows]

    # ---- incidents (evidence_store/incidents.py) ---------------------------------------------------------------

    def list_incidents(self, tenant_id: str, **filters):
        return inc.list_incidents(self, tenant_id, **filters)

    def get_incident(self, tenant_id: str, incident_id: str):
        return inc.get_incident(self, tenant_id, incident_id)

    def incident_verdicts(self, tenant_id: str, incident_id: str, limit: int = 100, offset: int = 0):
        return inc.incident_verdicts(self, tenant_id, incident_id, limit, offset)

    def incident_summary(self, tenant_id: str) -> dict:
        return inc.summary(self, tenant_id)

    def set_incident_status(self, tenant_id: str, incident_id: str, new_status: str,
                            actor: str = "system", reason: Optional[str] = None) -> dict:
        return inc.set_status(self, tenant_id, incident_id, new_status, actor, reason)

    def merge_incidents(self, tenant_id: str, source_id: str, target_id: str,
                        actor: str = "system", reason: Optional[str] = None) -> dict:
        return inc.merge(self, tenant_id, source_id, target_id, actor, reason)

    def split_incident(self, tenant_id: str, incident_id: str, verdict_ids: list,
                       actor: str = "system", reason: Optional[str] = None) -> dict:
        return inc.split(self, tenant_id, incident_id, verdict_ids, actor, reason)

    def backfill_incidents(self, tenant_id: str) -> int:
        return inc.backfill(self, tenant_id)

    def close(self) -> None:
        """Close the SQLite connection (the pending flow counts are written first)."""
        for pending in (self.flows, self.subjects):
            try:
                pending.flush()
            except Exception:
                logger.debug("pending counts not written at close", exc_info=True)
        self._conn.close()


# ---------------------------------------------------------------------------
# Module-level singleton (used by the server / pipeline)
# ---------------------------------------------------------------------------

_store: Optional[EvidenceStore] = None


def get_store(db_path: str | Path | None = None) -> EvidenceStore:
    """
    Return (or lazily create) the module-level EvidenceStore singleton.

    db_path defaults to None (not `_DEFAULT_DB_PATH` directly) so the
    module-level `_DEFAULT_DB_PATH` is looked up FRESH on every call
    rather than bound once at function-definition time (a Python default-
    argument gotcha: `def get_store(db_path=_DEFAULT_DB_PATH)` would
    capture whatever `_DEFAULT_DB_PATH` was when this module was first
    imported, silently ignoring any later `monkeypatch.setattr(store_
    module, "_DEFAULT_DB_PATH", ...)` a test tries to apply — which is
    exactly the isolation tests in api/test_integration.py rely on).
    """
    global _store
    if _store is None:
        _store = EvidenceStore(db_path=db_path if db_path is not None else _DEFAULT_DB_PATH)
    return _store


def reset_store() -> None:
    """Test-only: close and clear the singleton."""
    global _store
    if _store is not None:
        _store.close()
        _store = None


# ---------------------------------------------------------------------------
# Queue consumer — Phase 5's output → Evidence Store
# ---------------------------------------------------------------------------

async def store_from_queue(
    in_queue,
    store: Optional[EvidenceStore] = None,
    max_items: int | None = None,
) -> None:
    """
    Async consumer: pulls ExplainedVerdict objects off in_queue and appends
    each to the Evidence Store. Errors on individual items are logged and
    skipped (store is best-effort for the pipeline's liveness; evidence
    integrity is maintained for successfully-stored items).
    """
    if store is None:
        store = get_store()
    processed = 0
    while max_items is None or processed < max_items:
        ev = await in_queue.get()
        try:
            idx = store.append(ev)
            logger.info("Stored ExplainedVerdict at row_index=%d", idx)
        except Exception as exc:
            logger.error("Failed to store ExplainedVerdict: %s", exc)
        processed += 1
