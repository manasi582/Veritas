"""
Making a restore visible.

`veritas restore` rewinds the databases to a backup. That is legitimate, but left unrecorded it looks exactly like tampering: the live
chain is shorter than the signed checkpoints the witnesses hold, and the audit log forgets what happened in between. So:

  * the restore writes a marker (RESTORE_PENDING.json) naming the backup and, for each organization, what the live data held before
    (records, chain head) and which signed checkpoints described the history being set aside;
  * on its next start the server turns the marker into a signed RESTORE_EVENT in each organization's chain, an audit-log entry, and a
    floor under the checkpoint numbers so that no checkpoint number is ever used twice;
  * the stand-alone verifier reads the RESTORE_EVENT and reports the set-aside checkpoints as history a recorded restore removed.

The marker holds counts, hashes and checkpoint numbers. It holds no personal data.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("restore_notice")
MARKER = "RESTORE_PENDING.json"


def _orgs(db: Optional[Path]) -> Dict[str, dict]:
    """
    Per organization in an evidence database: records, chain head, and its checkpoints {cp_seq: checkpoint_id}.
    The database is read from a temporary copy (with its write-ahead log), so reading the safety copy never changes it.
    """
    import shutil
    import tempfile
    out: Dict[str, dict] = {}
    if db is None or not Path(db).exists():
        return out
    with tempfile.TemporaryDirectory(prefix="veritas-restore-read-") as scratch:
        copy = Path(scratch) / "evidence.db"
        shutil.copy2(db, copy)
        for suffix in ("-wal", "-shm"):
            if Path(str(db) + suffix).exists():
                shutil.copy2(str(db) + suffix, str(copy) + suffix)
        conn = sqlite3.connect(str(copy))
        try:
            conn.row_factory = sqlite3.Row
            for r in conn.execute("SELECT tenant_id, COUNT(*) AS n FROM evidence WHERE tenant_id IS NOT NULL AND tenant_id != '' GROUP BY tenant_id"):
                head = conn.execute("SELECT row_hash FROM evidence WHERE tenant_id = ? ORDER BY row_index DESC LIMIT 1", (r["tenant_id"],)).fetchone()
                out[r["tenant_id"]] = {"records": r["n"], "head": head["row_hash"] if head else None, "checkpoints": {}}
            try:
                for r in conn.execute("SELECT org, cp_seq, checkpoint_id FROM checkpoints"):
                    out.setdefault(r["org"], {"records": 0, "head": None, "checkpoints": {}})["checkpoints"][r["cp_seq"]] = r["checkpoint_id"]
            except sqlite3.OperationalError:
                pass                                # anchoring was never on: no checkpoints
        finally:
            conn.close()
    return out


def write_marker(root: Path, backup: Path, before_db: Optional[Path], after_db: Path, actor: str = "") -> Optional[Path]:
    """Called by the restore, after the databases are in place. Returns the marker's path, or None if it could not be written."""
    try:
        before, after = _orgs(before_db), _orgs(after_db)
        orgs: Dict[str, Any] = {}
        for org, b in before.items():
            kept = after.get(org, {}).get("checkpoints", {})
            away = sorted(n for n, cid in b["checkpoints"].items() if kept.get(n) != cid)
            orgs[org] = {"records_before": b["records"], "head_before": b["head"], "restored_away": away}
        for org in after:
            orgs.setdefault(org, {"records_before": 0, "head_before": None, "restored_away": []})
        marker = {"backup": backup.name, "restored_at": datetime.now(timezone.utc).isoformat(), "actor": actor or os.environ.get("SUDO_USER", ""),
                  "orgs": orgs}
        path = Path(root) / MARKER
        path.write_text(json.dumps(marker, indent=1, sort_keys=True), encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return path
    except Exception:
        logger.warning("could not write the restore marker", exc_info=True)
        return None


def apply_pending(store, root: Path, manager=None) -> int:
    """At start-up: record a pending restore in the chain, the audit log and the checkpoint numbering. Returns events written."""
    path = Path(root) / MARKER
    if not path.exists():
        return 0
    try:
        marker = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.warning("the restore marker is unreadable and was ignored", exc_info=True)
        return 0
    from audit_log.store import get_audit_store
    from evidence_store import canonical as cn
    restored_at = datetime.fromisoformat(marker["restored_at"])
    written = 0
    for org, info in sorted((marker.get("orgs") or {}).items()):
        head = store.chain_head(org)
        away = [int(n) for n in info.get("restored_away", [])]
        if head["record_count"]:
            with store.writer():
                store._append_event(org, cn.RESTORE_EVENT, "restore", lambda event_id, seq: cn.restore_event_body(
                    org, seq, event_id, marker["backup"], restored_at, info.get("records_before", 0), head["record_count"],
                    info.get("head_before"), away, datetime.now(timezone.utc), marker.get("actor") or None))
            written += 1
        if manager is not None and away:
            manager.raise_floor(org, max(away))
        get_audit_store().log("RESTORE", actor_name=marker.get("actor") or "system", org_id=org, resource="backup:" + marker["backup"],
                              detail={"records_before": info.get("records_before", 0), "records_after": head["record_count"],
                                      "dropped_records": max(0, info.get("records_before", 0) - head["record_count"]),
                                      "checkpoints_set_aside": away, "restored_at": marker["restored_at"]})
    try:
        path.rename(path.with_suffix(".done"))
    except OSError:
        path.unlink(missing_ok=True)
    logger.warning("A restore from %s was recorded in the evidence chain and the audit log", marker.get("backup"))
    return written
