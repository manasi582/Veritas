"""
Incidents: a view over the verdicts, never a replacement for them (phase T2, docs/TRUST_VISIBILITY_PLAN.md).

Every verdict stays in the evidence chain exactly as before. Verdicts that are the same finding of the same kind in
the same place (same fingerprint, see incidents/template.py) are attached to one incident row that carries the count,
first and last time seen, the highest severity and an hourly count for a sparkline.

What is part of the chain: every change of an incident's status, a reopening by the system (RECUR), a merge and a
split are INCIDENT_EVENT records. An incident's `status` column is a cache that verify_chain replays and compares,
like a verdict's. The grouping itself (which verdict is in which incident) is not signed: it can be recomputed and
an analyst can correct it with split and merge.

All functions here are called with the store's write lock held (the store's own methods take it).
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from evidence_store import canonical as cn
from incidents.template import fingerprint

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
_RANK_NAME = {v: k for k, v in SEVERITY_RANK.items()}
STATUSES = ("OPEN", "ACKNOWLEDGED", "RESOLVED")
# an analyst's steps; RESOLVED goes back to OPEN only by the system (RECUR)
STATUS_STEPS = {"OPEN": ["ACKNOWLEDGED", "RESOLVED"], "ACKNOWLEDGED": ["RESOLVED"], "RESOLVED": []}
LEGACY_TEMPLATE = "(finding from before grouping; wording not recorded)"
BUCKET_SECONDS = 3600
SPARK_HOURS = 24


def enabled() -> bool:
    return os.environ.get("VERITAS_INCIDENTS", "on").strip().lower() not in ("off", "0", "false", "no")


def grace_seconds() -> int:
    try:
        return max(0, int(os.environ.get("VERITAS_INCIDENT_GRACE_SECONDS", "3600")))
    except ValueError:
        return 3600


def create_tables(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id     TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL,
            number          INTEGER NOT NULL,
            rule_id         TEXT NOT NULL,
            source_system   TEXT NOT NULL,
            field           TEXT NOT NULL,
            template        TEXT NOT NULL,
            hint            TEXT,
            status          TEXT NOT NULL DEFAULT 'OPEN',
            severity        TEXT NOT NULL,
            severity_rank   INTEGER NOT NULL,
            breach_candidate INTEGER NOT NULL DEFAULT 0,
            count           INTEGER NOT NULL DEFAULT 0,
            first_seen      TEXT NOT NULL,
            last_seen       TEXT NOT NULL,
            resolved_at     TEXT,
            recurred_count  INTEGER NOT NULL DEFAULT 0,
            last_recurred_at TEXT,
            merged_into     TEXT
        )""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_number ON incidents(tenant_id, number)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_list ON incidents(tenant_id, merged_into, last_seen)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incident_fingerprints (
            tenant_id TEXT NOT NULL, fingerprint TEXT NOT NULL, incident_id TEXT NOT NULL,
            PRIMARY KEY (tenant_id, fingerprint))""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS verdict_incident (
            verdict_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, incident_id TEXT NOT NULL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_verdict_incident ON verdict_incident(incident_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incident_buckets (
            incident_id TEXT NOT NULL, bucket INTEGER NOT NULL, n INTEGER NOT NULL,
            PRIMARY KEY (incident_id, bucket))""")


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def _bucket(moment: datetime) -> int:
    return int(moment.timestamp()) // BUCKET_SECONDS


def _event(store, tenant: str, incident_id: str, action: str, old: Optional[str], new: Optional[str], actor: str,
           reason: Optional[str], at: datetime, other_id: Optional[str] = None, moved: Optional[int] = None) -> None:
    store._append_event(tenant, cn.INCIDENT_EVENT, incident_id,
                        lambda event_id, seq: cn.incident_event_body(
                            tenant, seq, event_id, incident_id, action, old, new, actor, reason, at, other_id, moved))


# --------------------------------------------------------------------------- grouping at ingest

def attach(store, tenant: str, verdict_id: str, rule_id: str, severity: str, source_system: str, field: str,
           breach: bool, template: str, hint: Optional[str], at: Optional[datetime] = None) -> str:
    """Put one verdict into its incident (creating it, or reopening a resolved one). Returns the incident id."""
    conn = store._conn
    at = at or datetime.now(timezone.utc)
    fp = fingerprint(tenant, rule_id, source_system, field, template)
    rank = SEVERITY_RANK.get(severity, 1)
    row = conn.execute("SELECT incident_id FROM incident_fingerprints WHERE tenant_id = ? AND fingerprint = ?",
                       (tenant, fp)).fetchone()
    if row is None:
        incident_id = str(uuid.uuid4())
        number = (conn.execute("SELECT MAX(number) AS m FROM incidents WHERE tenant_id = ?",
                               (tenant,)).fetchone()["m"] or 0) + 1
        conn.execute("""
            INSERT INTO incidents (incident_id, tenant_id, number, rule_id, source_system, field, template, hint,
                                   status, severity, severity_rank, breach_candidate, count, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, 0, ?, ?)""",
                     (incident_id, tenant, number, rule_id, source_system, field, template, hint,
                      severity, rank, 1 if breach else 0, _iso(at), _iso(at)))
        conn.execute("INSERT INTO incident_fingerprints (tenant_id, fingerprint, incident_id) VALUES (?, ?, ?)",
                     (tenant, fp, incident_id))
    else:
        incident_id = row["incident_id"]
    inc = conn.execute("SELECT status, resolved_at, severity_rank FROM incidents WHERE incident_id = ?",
                       (incident_id,)).fetchone()
    if inc["status"] == "RESOLVED" and inc["resolved_at"]:
        resolved = datetime.fromisoformat(inc["resolved_at"])
        if (at - resolved).total_seconds() >= grace_seconds():
            _event(store, tenant, incident_id, "RECUR", "RESOLVED", "OPEN", "system",
                   "the same finding appeared again after the incident was resolved", at)
            conn.execute("UPDATE incidents SET status = 'OPEN', resolved_at = NULL, "
                         "recurred_count = recurred_count + 1, last_recurred_at = ? WHERE incident_id = ?",
                         (_iso(at), incident_id))
    new_rank = max(inc["severity_rank"], rank)
    conn.execute("""
        UPDATE incidents SET count = count + 1, last_seen = MAX(last_seen, ?), severity_rank = ?, severity = ?,
                             breach_candidate = MAX(breach_candidate, ?)
        WHERE incident_id = ?""", (_iso(at), new_rank, _RANK_NAME[new_rank], 1 if breach else 0, incident_id))
    conn.execute("INSERT OR REPLACE INTO verdict_incident (verdict_id, tenant_id, incident_id) VALUES (?, ?, ?)",
                 (verdict_id, tenant, incident_id))
    conn.execute("""INSERT INTO incident_buckets (incident_id, bucket, n) VALUES (?, ?, 1)
                    ON CONFLICT(incident_id, bucket) DO UPDATE SET n = n + 1""", (incident_id, _bucket(at)))
    return incident_id


# --------------------------------------------------------------------------- reading

def _row(r, buckets: Optional[Dict[int, int]] = None) -> dict:
    d = {k: r[k] for k in ("incident_id", "number", "rule_id", "source_system", "field", "template", "hint",
                           "status", "severity", "count", "first_seen", "last_seen", "resolved_at",
                           "recurred_count", "last_recurred_at")}
    d["breach_candidate"] = bool(r["breach_candidate"])
    d["recurred"] = r["recurred_count"] > 0
    if buckets is not None:
        now = _bucket(datetime.now(timezone.utc))
        d["sparkline"] = [buckets.get(b, 0) for b in range(now - SPARK_HOURS + 1, now + 1)]
    return d


def _spark(conn, ids: List[str]) -> Dict[str, Dict[int, int]]:
    out: Dict[str, Dict[int, int]] = {i: {} for i in ids}
    if not ids:
        return out
    since = _bucket(datetime.now(timezone.utc)) - SPARK_HOURS + 1
    marks = ",".join("?" * len(ids))
    for r in conn.execute(f"SELECT incident_id, bucket, n FROM incident_buckets "
                          f"WHERE bucket >= ? AND incident_id IN ({marks})", [since, *ids]):
        out[r["incident_id"]][r["bucket"]] = r["n"]
    return out


def list_incidents(store, tenant: str, status: Optional[str] = None, severity: Optional[str] = None,
                   source_system: Optional[str] = None, recurred: bool = False, limit: int = 100,
                   offset: int = 0) -> Tuple[List[dict], int]:
    where, args = ["tenant_id = ?", "merged_into IS NULL"], [tenant]
    if status:
        where.append("status = ?"); args.append(status.upper())
    if severity:
        where.append("severity = ?"); args.append(severity.upper())
    if source_system:
        where.append("source_system = ?"); args.append(source_system)
    if recurred:
        where.append("recurred_count > 0")
    clause = " AND ".join(where)
    with store._lock:
        total = store._conn.execute(f"SELECT COUNT(*) AS n FROM incidents WHERE {clause}", args).fetchone()["n"]
        rows = store._conn.execute(
            f"SELECT * FROM incidents WHERE {clause} "
            "ORDER BY CASE status WHEN 'RESOLVED' THEN 1 ELSE 0 END, severity_rank DESC, last_seen DESC "
            "LIMIT ? OFFSET ?", [*args, max(1, min(limit, 500)), max(0, offset)]).fetchall()
        spark = _spark(store._conn, [r["incident_id"] for r in rows])
        return [_row(r, spark[r["incident_id"]]) for r in rows], total


def get_incident(store, tenant: str, incident_id: str) -> Optional[dict]:
    with store._lock:
        r = store._conn.execute("SELECT * FROM incidents WHERE tenant_id = ? AND incident_id = ?",
                                (tenant, incident_id)).fetchone()
        if r is None:
            return None
        d = _row(r, _spark(store._conn, [incident_id])[incident_id])
        d["merged_into"] = r["merged_into"]
        return d


def incident_verdicts(store, tenant: str, incident_id: str, limit: int = 100, offset: int = 0) -> List[dict]:
    with store._lock:
        ids = [r["verdict_id"] for r in store._conn.execute(
            "SELECT vi.verdict_id FROM verdict_incident vi JOIN evidence e ON e.verdict_id = vi.verdict_id "
            "WHERE vi.tenant_id = ? AND vi.incident_id = ? ORDER BY e.row_index DESC LIMIT ? OFFSET ?",
            (tenant, incident_id, max(1, min(limit, 500)), max(0, offset))).fetchall()]
    return [v for v in (store.get_by_verdict_id(tenant, i) for i in ids) if v]


def summary(store, tenant: str) -> dict:
    with store._lock:
        c = store._conn
        by_status = {r["status"]: r["n"] for r in c.execute(
            "SELECT status, COUNT(*) AS n FROM incidents WHERE tenant_id = ? AND merged_into IS NULL "
            "GROUP BY status", (tenant,))}
        grouped = c.execute("SELECT COUNT(*) AS n FROM verdict_incident WHERE tenant_id = ?", (tenant,)).fetchone()["n"]
        total = c.execute("SELECT COUNT(*) AS n FROM evidence WHERE tenant_id = ? AND record_type = 'VERDICT'",
                          (tenant,)).fetchone()["n"]
        recurred = c.execute("SELECT COUNT(*) AS n FROM incidents WHERE tenant_id = ? AND merged_into IS NULL "
                             "AND recurred_count > 0", (tenant,)).fetchone()["n"]
    return {"incidents": sum(by_status.values()), "by_status": {s: by_status.get(s, 0) for s in STATUSES},
            "recurred": recurred, "verdicts": total, "verdicts_grouped": grouped}


# --------------------------------------------------------------------------- changing

def set_status(store, tenant: str, incident_id: str, new_status: str, actor: str, reason: Optional[str]) -> dict:
    new_status = new_status.upper()
    if new_status not in STATUSES:
        raise ValueError(f"Invalid status: {new_status!r}")
    with store._lock:
        r = store._conn.execute("SELECT status, merged_into FROM incidents WHERE tenant_id = ? AND incident_id = ?",
                                (tenant, incident_id)).fetchone()
        if r is None:
            raise ValueError(f"Incident not found: {incident_id!r}")
        if r["merged_into"]:
            raise ValueError("This incident was merged into another one; change that one instead.")
        if new_status not in STATUS_STEPS[r["status"]]:
            raise ValueError(f"Invalid status transition: {r['status']!r} → {new_status!r}. "
                             f"Allowed: {STATUS_STEPS[r['status']]}")
        at = datetime.now(timezone.utc)
        try:
            _event(store, tenant, incident_id, "STATUS", r["status"], new_status, actor or "system", reason, at)
            store._conn.execute("UPDATE incidents SET status = ?, resolved_at = ? WHERE incident_id = ?",
                                (new_status, _iso(at) if new_status == "RESOLVED" else None, incident_id))
            store._conn.commit()
        except Exception:
            store._conn.rollback()
            raise
    return get_incident(store, tenant, incident_id)


def _recompute(conn, incident_id: str) -> None:
    r = conn.execute(
        "SELECT COUNT(*) AS n, MIN(e.appended_at) AS lo, MAX(e.appended_at) AS hi, MAX(CASE e.severity "
        "WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END) AS rank, MAX(e.breach_candidate) AS breach "
        "FROM verdict_incident vi JOIN evidence e ON e.verdict_id = vi.verdict_id WHERE vi.incident_id = ?",
        (incident_id,)).fetchone()
    conn.execute("DELETE FROM incident_buckets WHERE incident_id = ?", (incident_id,))
    for e in conn.execute("SELECT e.appended_at FROM verdict_incident vi JOIN evidence e ON e.verdict_id = vi.verdict_id "
                          "WHERE vi.incident_id = ?", (incident_id,)).fetchall():
        b = _bucket(datetime.fromisoformat(e["appended_at"]))
        conn.execute("INSERT INTO incident_buckets (incident_id, bucket, n) VALUES (?, ?, 1) "
                     "ON CONFLICT(incident_id, bucket) DO UPDATE SET n = n + 1", (incident_id, b))
    if r["n"]:
        rank = r["rank"] or 1
        conn.execute("UPDATE incidents SET count = ?, first_seen = ?, last_seen = ?, severity_rank = ?, severity = ?, "
                     "breach_candidate = ? WHERE incident_id = ?",
                     (r["n"], r["lo"], r["hi"], rank, _RANK_NAME[rank], r["breach"] or 0, incident_id))
    else:
        conn.execute("UPDATE incidents SET count = 0 WHERE incident_id = ?", (incident_id,))


def merge(store, tenant: str, source_id: str, target_id: str, actor: str, reason: Optional[str]) -> dict:
    """Fold `source_id` into `target_id`: its verdicts and fingerprints move, future matches land in the target."""
    if source_id == target_id:
        raise ValueError("An incident cannot be merged into itself.")
    with store._lock:
        c = store._conn
        rows = {r["incident_id"]: r for r in c.execute(
            "SELECT * FROM incidents WHERE tenant_id = ? AND incident_id IN (?, ?)", (tenant, source_id, target_id))}
        if len(rows) != 2:
            raise ValueError("Incident not found.")
        if rows[source_id]["merged_into"] or rows[target_id]["merged_into"]:
            raise ValueError("One of the incidents was already merged into another.")
        moved = rows[source_id]["count"]
        at = datetime.now(timezone.utc)
        try:
            _event(store, tenant, target_id, "MERGE", None, None, actor or "system", reason, at,
                   other_id=source_id, moved=moved)
            c.execute("UPDATE verdict_incident SET incident_id = ? WHERE incident_id = ?", (target_id, source_id))
            c.execute("UPDATE incident_fingerprints SET incident_id = ? WHERE incident_id = ?", (target_id, source_id))
            c.execute("UPDATE incidents SET merged_into = ?, count = 0 WHERE incident_id = ?", (target_id, source_id))
            c.execute("DELETE FROM incident_buckets WHERE incident_id = ?", (source_id,))
            _recompute(c, target_id)
            c.commit()
        except Exception:
            c.rollback()
            raise
    return get_incident(store, tenant, target_id)


def split(store, tenant: str, incident_id: str, verdict_ids: List[str], actor: str, reason: Optional[str]) -> dict:
    """Move the named verdicts of an incident into a new incident of their own."""
    if not verdict_ids:
        raise ValueError("Name the verdicts to move.")
    with store._lock:
        c = store._conn
        src = c.execute("SELECT * FROM incidents WHERE tenant_id = ? AND incident_id = ? AND merged_into IS NULL",
                        (tenant, incident_id)).fetchone()
        if src is None:
            raise ValueError("Incident not found.")
        marks = ",".join("?" * len(verdict_ids))
        found = [r["verdict_id"] for r in c.execute(
            f"SELECT verdict_id FROM verdict_incident WHERE tenant_id = ? AND incident_id = ? "
            f"AND verdict_id IN ({marks})", [tenant, incident_id, *verdict_ids])]
        if not found:
            raise ValueError("None of those verdicts belongs to this incident.")
        if len(found) == src["count"]:
            raise ValueError("That is every verdict of the incident; splitting would leave it empty.")
        new_id = str(uuid.uuid4())
        number = (c.execute("SELECT MAX(number) AS m FROM incidents WHERE tenant_id = ?", (tenant,)).fetchone()["m"]
                  or 0) + 1
        at = datetime.now(timezone.utc)
        try:
            c.execute("""INSERT INTO incidents (incident_id, tenant_id, number, rule_id, source_system, field,
                                template, hint, status, severity, severity_rank, count, first_seen, last_seen)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, 0, ?, ?)""",
                      (new_id, tenant, number, src["rule_id"], src["source_system"], src["field"], src["template"],
                       src["hint"], src["severity"], src["severity_rank"], _iso(at), _iso(at)))
            c.execute("INSERT INTO incident_fingerprints (tenant_id, fingerprint, incident_id) VALUES (?, ?, ?)",
                      (tenant, "split:" + new_id, new_id))
            for vid in found:
                c.execute("UPDATE verdict_incident SET incident_id = ? WHERE verdict_id = ?", (new_id, vid))
            _event(store, tenant, new_id, "SPLIT", None, None, actor or "system", reason, at,
                   other_id=incident_id, moved=len(found))
            _recompute(c, incident_id)
            _recompute(c, new_id)
            c.commit()
        except Exception:
            c.rollback()
            raise
    return get_incident(store, tenant, new_id)


# --------------------------------------------------------------------------- older findings, and the chain check

def backfill(store, tenant: str, batch: int = 500) -> int:
    """
    Group verdicts that were stored before incidents existed (or whose grouping failed). Their wording was never
    kept, so they are grouped by rule, system and field only. Returns how many were attached.
    """
    done = 0
    while True:
        with store._lock:
            rows = store._conn.execute(
                "SELECT e.verdict_id, e.appended_at, e.rule_id, e.severity, e.source_system, e.breach_candidate, "
                "e.payload_json, e.hash_version FROM evidence e LEFT JOIN verdict_incident vi ON vi.verdict_id = e.verdict_id "
                "WHERE e.tenant_id = ? AND e.record_type = 'VERDICT' AND vi.verdict_id IS NULL "
                "ORDER BY e.row_index LIMIT ?", (tenant, batch)).fetchall()
            if not rows:
                return done
            try:
                for r in rows:
                    field = store._decode(r).get("field") or ""
                    attach(store, tenant, r["verdict_id"], r["rule_id"], r["severity"], r["source_system"], field,
                           bool(r["breach_candidate"]), LEGACY_TEMPLATE, None, datetime.fromisoformat(r["appended_at"]))
                store._conn.commit()
            except Exception:
                store._conn.rollback()
                raise
            done += len(rows)


def verify_event(signed: dict, replay: Dict[str, str]) -> bool:
    """One INCIDENT_EVENT during verify_chain: True if it is a valid step. `replay` maps incident_id to its status."""
    action, iid = signed.get("action"), signed.get("incident_id")
    if not iid:
        return False
    if action == "STATUS":
        old = replay.get(iid, "OPEN")
        if signed.get("old_status") != old or signed.get("new_status") not in STATUS_STEPS.get(old, []):
            return False
        replay[iid] = signed["new_status"]
        return True
    if action == "RECUR":
        if replay.get(iid, "OPEN") != "RESOLVED" or signed.get("old_status") != "RESOLVED" \
                or signed.get("new_status") != "OPEN":
            return False
        replay[iid] = "OPEN"
        return True
    if action in ("MERGE", "SPLIT"):
        return bool(signed.get("other_id"))
    return False
