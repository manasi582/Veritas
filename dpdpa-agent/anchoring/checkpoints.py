"""
Checkpoints: signed statements of an organization's chain head, copied to witnesses the server cannot alter.

  checkpoint = { type: "CHECKPOINT", checkpoint_id, cp_seq, org, last_seq, head_hash, record_count, created_at,
                 prev_checkpoint_hash (absent for the first), key_id }  + signature
  signed bytes  = "veritas-checkpoint-v1" LF canonical_json(checkpoint without the signature)
  checkpoint_hash = SHA-256 of those bytes; the next checkpoint's prev_checkpoint_hash is this value

Everything is written through the evidence store's own lock, so a checkpoint is always taken between two records.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional

from anchoring import keys as anchor_keys
from anchoring.config import AnchorConfig
from anchoring.sinks import Sink, build_sinks
from evidence_store import canonical as cn

logger = logging.getLogger("veritas.anchoring")

DOMAIN = "veritas-checkpoint-v1"
PENDING, WITNESSED = "PENDING", "WITNESSED"
TICK_SECONDS = 30
RETRY_BASE_SECONDS = 30
HEALTH_CACHE_SECONDS = 30


def signed_bytes(body: Dict[str, Any]) -> bytes:
    return (DOMAIN + "\n" + cn.canonical_json(body)).encode("utf-8")


def checkpoint_hash(body: Dict[str, Any]) -> str:
    return hashlib.sha256(signed_bytes(body)).hexdigest()


class AnchorManager:
    def __init__(self, store, config: AnchorConfig, sinks: Optional[List[Sink]] = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.store = store
        self.config = config
        self.sinks: List[Sink] = sinks if sinks is not None else build_sinks(config.sinks)
        self._clock = clock
        self._health_cache: tuple = (0.0, [])
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.ensure_schema()

    # ------------------------------------------------------------------ schema
    def ensure_schema(self) -> None:
        with self.store.writer() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    checkpoint_id TEXT PRIMARY KEY, org TEXT NOT NULL, cp_seq INTEGER NOT NULL,
                    last_seq INTEGER NOT NULL, head_hash TEXT NOT NULL, record_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL, prev_checkpoint_hash TEXT, key_id TEXT NOT NULL,
                    signature TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING',
                    UNIQUE (org, cp_seq));
                CREATE TABLE IF NOT EXISTS checkpoint_receipts (
                    checkpoint_id TEXT NOT NULL, sink TEXT NOT NULL, acked_at TEXT, receipt TEXT, error TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0, last_attempt TEXT,
                    PRIMARY KEY (checkpoint_id, sink));
                CREATE INDEX IF NOT EXISTS idx_checkpoints_org ON checkpoints(org, cp_seq);
                CREATE TABLE IF NOT EXISTS anchor_floor (
                    org TEXT PRIMARY KEY, floor INTEGER NOT NULL, set_at TEXT NOT NULL);
            """)
            if not conn.execute("SELECT 1 FROM schema_version WHERE version = 3").fetchone():
                conn.execute("INSERT INTO schema_version (version, name, applied_at) VALUES (3, 'anchoring', ?)",
                             (self._clock().isoformat(),))

    # ------------------------------------------------------------------ making checkpoints
    def _body_of(self, row) -> Dict[str, Any]:
        body = {"type": "CHECKPOINT", "checkpoint_id": row["checkpoint_id"], "cp_seq": row["cp_seq"], "org": row["org"],
                "last_seq": row["last_seq"], "head_hash": row["head_hash"], "record_count": row["record_count"],
                "created_at": row["created_at"], "key_id": row["key_id"]}
        if row["prev_checkpoint_hash"]:
            body["prev_checkpoint_hash"] = row["prev_checkpoint_hash"]
        return body

    def full_checkpoint(self, row) -> Dict[str, Any]:
        return {**self._body_of(row), "signature": row["signature"]}

    def _latest(self, conn, org: str):
        return conn.execute("SELECT * FROM checkpoints WHERE org = ? ORDER BY cp_seq DESC LIMIT 1", (org,)).fetchone()

    def due(self, org: str) -> bool:
        head = self.store.chain_head(org)
        if head["record_count"] == 0:
            return False
        last = self._latest(self.store._conn, org)
        if last is None:
            return True
        if head["head_hash"] == last["head_hash"]:
            return False
        if head["last_seq"] - last["last_seq"] >= self.config.every_n_records:
            return True
        age = (self._clock() - datetime.fromisoformat(last["created_at"].replace("Z", "+00:00"))).total_seconds()
        return age >= self.config.interval_minutes * 60

    def checkpoint_now(self, org: str) -> Optional[Dict[str, Any]]:
        """Take a checkpoint if the chain head moved since the last one. Returns it, or None if there was nothing new."""
        private, public_raw, key_id = anchor_keys.load_or_create()
        with self.store.writer() as conn:
            head = self.store.chain_head(org)
            if head["record_count"] == 0:
                return None
            last = self._latest(conn, org)
            if last is not None and last["head_hash"] == head["head_hash"]:
                return None
            fl = conn.execute("SELECT floor FROM anchor_floor WHERE org = ?", (org,)).fetchone()
            floor = fl["floor"] if fl else 0       # after a restore, numbers never repeat one a witness already holds
            body = {"type": "CHECKPOINT", "checkpoint_id": str(uuid.uuid4()),
                    "cp_seq": max(last["cp_seq"] if last else 0, floor) + 1, "org": org, "last_seq": head["last_seq"],
                    "head_hash": head["head_hash"], "record_count": head["record_count"],
                    "created_at": cn.rfc3339_ms(self._clock()), "key_id": key_id}
            if last is not None:
                body["prev_checkpoint_hash"] = checkpoint_hash(self._body_of(last))
            signature = private.sign(signed_bytes(body)).hex()
            conn.execute(
                "INSERT INTO checkpoints (checkpoint_id, org, cp_seq, last_seq, head_hash, record_count, created_at,"
                " prev_checkpoint_hash, key_id, signature, status) VALUES (?,?,?,?,?,?,?,?,?,?, 'PENDING')",
                (body["checkpoint_id"], org, body["cp_seq"], body["last_seq"], body["head_hash"], body["record_count"],
                 body["created_at"], body.get("prev_checkpoint_hash"), key_id, signature))
        logger.info("Checkpoint %s #%d for %s: seq %d, %d records", body["checkpoint_id"][:8], body["cp_seq"], org,
                    body["last_seq"], body["record_count"])
        self._audit("ANCHOR_CHECKPOINT", org, {"cp_seq": body["cp_seq"], "last_seq": body["last_seq"]})
        self.publish_pending(org)
        return {**body, "signature": signature}

    def raise_floor(self, org: str, floor: int) -> None:
        """Next checkpoints of `org` are numbered above `floor` (set after a restore, from the numbers it set aside)."""
        with self.store.writer() as conn:
            conn.execute("INSERT INTO anchor_floor (org, floor, set_at) VALUES (?, ?, ?) ON CONFLICT(org) DO UPDATE SET "
                         "floor = MAX(floor, excluded.floor), set_at = excluded.set_at", (org, int(floor), self._clock().isoformat()))

    # ------------------------------------------------------------------ witnessing
    def publish_pending(self, org: Optional[str] = None) -> None:
        if not self.sinks:
            return
        with self.store.writer() as conn:
            rows = conn.execute("SELECT * FROM checkpoints WHERE status = 'PENDING'" + (" AND org = ?" if org else "") +
                                " ORDER BY org, cp_seq", (org,) if org else ()).fetchall()
        for row in rows:
            self._publish(row)

    def _publish(self, row) -> None:
        cp = self.full_checkpoint(row)
        now = self._clock()
        for sink in self.sinks:
            with self.store.writer() as conn:
                rec = conn.execute("SELECT * FROM checkpoint_receipts WHERE checkpoint_id = ? AND sink = ?",
                                   (row["checkpoint_id"], sink.name)).fetchone()
            if rec is not None and rec["acked_at"]:
                continue
            attempts = rec["attempts"] if rec else 0
            if rec is not None and rec["last_attempt"]:       # back off after failures: 30 s, 1 min, 2 min ... up to ~32 min
                wait = RETRY_BASE_SECONDS * (2 ** min(attempts - 1, 6))
                if (now - datetime.fromisoformat(rec["last_attempt"])).total_seconds() < wait:
                    continue
            try:
                receipt, error = sink.publish(cp), None
            except Exception as e:                            # a broken witness must never stop the server
                receipt, error = None, str(e)[:300]
                logger.warning("Witness %s did not take checkpoint #%d of %s: %s", sink.name, row["cp_seq"], row["org"], e)
            with self.store.writer() as conn:
                conn.execute(
                    "INSERT INTO checkpoint_receipts (checkpoint_id, sink, acked_at, receipt, error, attempts, last_attempt)"
                    " VALUES (?,?,?,?,?,?,?) ON CONFLICT(checkpoint_id, sink) DO UPDATE SET acked_at=excluded.acked_at,"
                    " receipt=excluded.receipt, error=excluded.error, attempts=excluded.attempts, last_attempt=excluded.last_attempt",
                    (row["checkpoint_id"], sink.name, now.isoformat() if receipt else None, receipt, error,
                     attempts + 1, now.isoformat()))
        with self.store.writer() as conn:
            acked = conn.execute("SELECT COUNT(*) AS n FROM checkpoint_receipts WHERE checkpoint_id = ? AND acked_at IS NOT NULL",
                                 (row["checkpoint_id"],)).fetchone()["n"]
            if acked >= self.config.min_witnesses:
                conn.execute("UPDATE checkpoints SET status = 'WITNESSED' WHERE checkpoint_id = ?", (row["checkpoint_id"],))

    # ------------------------------------------------------------------ the loop
    def tick(self) -> None:
        for org in self.store.tenants():
            try:
                if self.due(org):
                    self.checkpoint_now(org)
            except Exception:
                logger.exception("Checkpoint for %s failed", org)
        try:
            self.publish_pending()
        except Exception:
            logger.exception("Publishing pending checkpoints failed")

    def _loop(self) -> None:
        while not self._stop.wait(TICK_SECONDS):
            self.tick()

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="veritas-anchoring", daemon=True)
            self._thread.start()
            logger.info("Anchoring on: every %.4g min or %d records, %d witness(es), %d needed",
                        self.config.interval_minutes, self.config.every_n_records, len(self.sinks), self.config.min_witnesses)

    def stop(self) -> None:
        """Stop the loop and take a last checkpoint so a clean shutdown leaves nothing unanchored."""
        self._stop.set()
        try:
            for org in self.store.tenants():
                self.checkpoint_now(org)
            self.publish_pending()
        except Exception:
            logger.exception("Final checkpoint failed")

    # ------------------------------------------------------------------ reading
    def list_checkpoints(self, org: str, limit: int = 50) -> List[Dict[str, Any]]:
        with self.store.writer() as conn:
            rows = conn.execute("SELECT * FROM checkpoints WHERE org = ? ORDER BY cp_seq DESC LIMIT ?", (org, limit)).fetchall()
            out = []
            for r in rows:
                receipts = conn.execute("SELECT sink, acked_at, receipt, error, attempts FROM checkpoint_receipts WHERE checkpoint_id = ?",
                                        (r["checkpoint_id"],)).fetchall()
                out.append({**self.full_checkpoint(r), "status": r["status"], "receipts": [dict(x) for x in receipts]})
        return out

    def all_checkpoints(self, org: str) -> Iterator[Dict[str, Any]]:
        with self.store.writer() as conn:
            rows = conn.execute("SELECT * FROM checkpoints WHERE org = ? ORDER BY cp_seq ASC", (org,)).fetchall()
        for r in rows:
            yield self.full_checkpoint(r)

    def witness_health(self) -> List[Dict[str, Any]]:
        t, cached = self._health_cache
        if time.time() - t < HEALTH_CACHE_SECONDS:
            return cached
        result = []
        for s in self.sinks:
            try:
                result.append(s.health())
            except Exception as e:
                result.append({"sink": s.name, "ok": False, "detail": str(e)})
        self._health_cache = (time.time(), result)
        return result

    def status(self, org: Optional[str] = None) -> Dict[str, Any]:
        now = self._clock()
        orgs = [org] if org else self.store.tenants()
        per_org = {}
        banner = False
        for o in orgs:
            head = self.store.chain_head(o)
            with self.store.writer() as conn:
                last = self._latest(conn, o)
                witnessed = conn.execute("SELECT * FROM checkpoints WHERE org = ? AND status = 'WITNESSED' ORDER BY cp_seq DESC LIMIT 1", (o,)).fetchone()
                pending = conn.execute("SELECT COUNT(*) AS n FROM checkpoints WHERE org = ? AND status = 'PENDING'", (o,)).fetchone()["n"]
            unanchored = head["last_seq"] - (witnessed["last_seq"] if witnessed else 0)
            age = None
            if witnessed:
                age = (now - datetime.fromisoformat(witnessed["created_at"].replace("Z", "+00:00"))).total_seconds()
            stale = unanchored > 0 and (age is None or age > 2 * self.config.interval_minutes * 60)
            banner = banner or (self.config.enabled and stale)
            per_org[o] = {"last_checkpoint_at": last["created_at"] if last else None,
                          "last_witnessed_at": witnessed["created_at"] if witnessed else None,
                          "pending": pending, "unanchored_records": unanchored, "stale": bool(stale)}
        return {"enabled": self.config.enabled, "interval_minutes": self.config.interval_minutes,
                "min_witnesses": self.config.min_witnesses, "witnesses": self.witness_health() if self.config.enabled else [],
                "orgs": per_org, "banner": bool(banner), "problems": self.config.problems,
                "single_witness": self.config.enabled and self.config.min_witnesses < 2}

    # ------------------------------------------------------------------ audit
    def _audit(self, action: str, org: str, detail: dict) -> None:
        try:
            from audit_log.store import get_audit_store
            get_audit_store().log(action, actor_name="system", org_id=org, detail=detail)
        except Exception:
            pass


_manager: Optional[AnchorManager] = None
_lock = threading.Lock()


def get_manager() -> Optional[AnchorManager]:
    """The server's one manager, or None when anchoring is off."""
    global _manager
    with _lock:
        if _manager is None:
            from anchoring.config import load_config
            from evidence_store.store import get_store
            cfg = load_config()
            if not cfg.enabled:
                return None
            _manager = AnchorManager(get_store(), cfg)
        return _manager


def reset_manager() -> None:
    global _manager
    with _lock:
        m, _manager = _manager, None
    if m is not None:
        m._stop.set()
