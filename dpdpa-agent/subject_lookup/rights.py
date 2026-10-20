"""
Rights requests (access, erasure, correction): a record of who asked for what, which systems were observed to hold the
identifier, who confirmed each system, and when it closed. Creation, task creation, each confirmation and the closure
are events in the evidence chain; the request's status is a cache that the chain check replays.

Nothing here stores an identifier or the requester's name: the requester is an opaque reference (a ticket number), and
the identifiers are kept only as keyed tokens. After an erasure request closes, its tokens join the watch list: if the
identifier is observed again, ERASURE_001 is raised.

What this is not: a certificate that data was erased everywhere. It says where Veritas observed the identifier and who
confirmed their system.
"""
from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import veritas_recognizers as vr
from db_encryption import decrypt_field
from evidence_store import canonical as cn
from subject_lookup.index import CATEGORIES, InvalidIdentifier, clean_identifier

TYPES = ("access", "erasure", "correction", "retention")
_REF = re.compile(r"^[ -~]{1,100}$")
_DIGIT_RUN = re.compile(r"\d{9,}")


class RequestError(ValueError):
    pass


def create_tables(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rights_requests (
            request_id TEXT PRIMARY KEY, org TEXT NOT NULL, type TEXT NOT NULL, received_at TEXT NOT NULL,
            due_at TEXT, status TEXT NOT NULL DEFAULT 'OPEN', requester_ref TEXT NOT NULL, token_ref TEXT,
            created_by TEXT NOT NULL, created_at TEXT NOT NULL, closed_at TEXT, lookup_json TEXT NOT NULL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rights_org ON rights_requests(org, created_at)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS request_tasks (
            request_id TEXT NOT NULL, system TEXT NOT NULL, owner TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN',
            confirmed_by TEXT, confirmed_at TEXT, note TEXT, PRIMARY KEY (request_id, system))""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS request_tokens (
            request_id TEXT NOT NULL, org TEXT NOT NULL, key_id TEXT NOT NULL, token TEXT NOT NULL, category TEXT NOT NULL,
            PRIMARY KEY (request_id, key_id, token, category))""")


def response_days() -> Optional[int]:
    """The response period, only if the administrator has set one. There is deliberately no default."""
    try:
        n = int(os.environ.get("VERITAS_RIGHTS_RESPONSE_DAYS", "") or 0)
    except ValueError:
        return None
    return n if n > 0 else None


def _check_ref(ref: str) -> str:
    ref = (ref or "").strip()
    if not _REF.match(ref):
        raise RequestError("The requester reference must be 1 to 100 plain characters (a ticket number, not a name).")
    if _DIGIT_RUN.search(ref) or vr.scan(ref):
        raise RequestError("The requester reference looks like it contains an identifier. Use an opaque reference such as a ticket number.")
    return ref


def _parse_date(value: Optional[str], what: str) -> Optional[datetime]:
    if value in (None, ""):
        return None
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise RequestError(f"{what} is not a valid date (use 2026-10-20 or 2026-10-20T10:00:00Z).")
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _owner_text(owners: Dict[str, dict], system: str) -> str:
    o = owners.get(system) or {}
    bits = [x for x in (o.get("team"), o.get("email"), o.get("slack_channel")) if x]
    return " · ".join(bits) if bits else "unassigned"


def _event(store, org: str, request_id: str, action: str, actor: str, at: datetime, **kw) -> Tuple[str, int, str]:
    store._append_event(org, cn.RIGHTS_EVENT, request_id,
                        lambda event_id, seq: cn.rights_event_body(org, seq, event_id, request_id, action, actor, at, **kw))
    row = store._conn.execute("SELECT seq, row_hash FROM evidence WHERE tenant_id = ? AND record_type = ? AND target_id = ? "
                              "ORDER BY seq DESC LIMIT 1", (org, cn.RIGHTS_EVENT, request_id)).fetchone()
    return action, row["seq"], row["row_hash"]


# --------------------------------------------------------------------------- create

def create_request(store, org: str, req_type: str, requester_ref: str, identifiers: List[Tuple[str, str]],
                   owners: Optional[Dict[str, dict]] = None, actor: str = "system", received_at: Optional[str] = None,
                   due_at: Optional[str] = None) -> dict:
    req_type = (req_type or "").lower()
    if req_type not in TYPES:
        raise RequestError("The type must be one of: " + ", ".join(TYPES) + ".")
    ref = _check_ref(requester_ref)
    if not identifiers:
        raise RequestError("Give at least one identifier to look up (phone, email, aadhaar, pan or card).")
    if len(identifiers) > 10:
        raise RequestError("At most 10 identifiers per request.")
    received = _parse_date(received_at, "received_at") or datetime.now(timezone.utc)
    due = _parse_date(due_at, "due_at")
    if due is None and response_days():
        due = received + timedelta(days=response_days())

    store.keyring.current(org, "lookup")          # make sure the keys exist, so the tokens below are kept for the watch list
    store.keyring.current(org, "agent")
    pairs: List[Tuple[str, str, str]] = []        # (category, key_id, token)
    lookup: List[dict] = []
    systems: Dict[str, dict] = {}
    for category, identifier in identifiers:
        try:
            tok = store.subjects.tokens_for_identifier(org, category, identifier)
        except InvalidIdentifier as e:
            raise RequestError(str(e))
        found = store.subjects.lookup_tokens(org, category, tok)
        pairs += [(category.lower(), k, t) for k, t in tok]
        lookup.append({"category": category.lower(), "token_prefix": tok[0][1][:8], "systems": found["systems"],
                       "verdicts": found["verdicts"][:20]})
        for s in found["systems"]:
            slot = systems.setdefault(s["system"], {"events": 0})
            slot["events"] += s["events"]
    owners = owners or {}
    request_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    system_names = sorted(systems)
    with store.writer() as conn:
        conn.execute("""INSERT INTO rights_requests (request_id, org, type, received_at, due_at, status, requester_ref,
                        token_ref, created_by, created_at, lookup_json) VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?)""",
                     (request_id, org, req_type, received.isoformat(), due.isoformat() if due else None, ref,
                      pairs[0][2][:8], actor, now.isoformat(), json.dumps(lookup, sort_keys=True)))
        for category, kid, token in pairs:
            conn.execute("INSERT OR IGNORE INTO request_tokens (request_id, org, key_id, token, category) VALUES (?, ?, ?, ?, ?)",
                         (request_id, org, kid, token, category))
        for name in system_names:
            conn.execute("INSERT INTO request_tasks (request_id, system, owner) VALUES (?, ?, ?)",
                         (request_id, name, _owner_text(owners, name)))
        _event(store, org, request_id, "CREATED", actor, now, request_type=req_type, identifiers=len(identifiers))
        _event(store, org, request_id, "TASKS_CREATED", actor, now, systems=system_names)
    return get_request(store, org, request_id)


def create_retention_task(store, org: str, systems: List[str], owners: Optional[Dict[str, dict]] = None, actor: str = "system",
                          detail: Optional[List[dict]] = None, today: Optional[datetime] = None) -> dict:
    """
    A retention review task: one task per system, asking its owner to confirm that data past its declared period was purged
    (or to justify keeping it). It has no identifiers and no watch list; each step is a chain entry like any request.
    `detail` is what the review found for these systems (field, period, due date); it is kept with the request for the record.
    """
    systems = sorted({s for s in systems if isinstance(s, str) and s})
    if not systems:
        raise RequestError("Name at least one system.")
    with store._lock:
        busy = {r["system"] for r in store._conn.execute(
            "SELECT t.system FROM request_tasks t JOIN rights_requests r ON r.request_id = t.request_id "
            "WHERE r.org = ? AND r.type = 'retention' AND r.status = 'OPEN' AND t.status = 'OPEN'", (org,))}
    if busy & set(systems):
        raise RequestError("There is already an open retention task for: " + ", ".join(sorted(busy & set(systems))) + ".")
    owners = owners or {}
    now = today or datetime.now(timezone.utc)
    request_id = str(uuid.uuid4())
    ref = f"RET-{now.strftime('%Y%m%d')}-{request_id[:6]}"
    lookup = [{"category": "retention", "token_prefix": "-", "verdicts": [],
               "systems": [{"system": s, "events": 0, "first_seen": now.isoformat(), "last_seen": now.isoformat()} for s in systems],
               "retention": detail or []}]
    with store.writer() as conn:
        conn.execute("""INSERT INTO rights_requests (request_id, org, type, received_at, due_at, status, requester_ref,
                        token_ref, created_by, created_at, lookup_json) VALUES (?, ?, 'retention', ?, NULL, 'OPEN', ?, NULL, ?, ?, ?)""",
                     (request_id, org, now.isoformat(), ref, actor, now.isoformat(), json.dumps(lookup, sort_keys=True)))
        for name in systems:
            conn.execute("INSERT INTO request_tasks (request_id, system, owner) VALUES (?, ?, ?)",
                         (request_id, name, _owner_text(owners, name)))
        _event(store, org, request_id, "CREATED", actor, now, request_type="retention", identifiers=0)
        _event(store, org, request_id, "TASKS_CREATED", actor, now, systems=systems)
    return get_request(store, org, request_id)


# --------------------------------------------------------------------------- change

def _tasks(conn, request_id: str) -> List[dict]:
    return [dict(r) for r in conn.execute("SELECT system, owner, status, confirmed_by, confirmed_at, note FROM request_tasks "
                                          "WHERE request_id = ? ORDER BY system", (request_id,))]


def confirm_task(store, org: str, request_id: str, system: str, actor: str, note: Optional[str] = None) -> dict:
    note = (note or "").strip()[:500] or None
    with store.writer() as conn:
        req = conn.execute("SELECT status, type FROM rights_requests WHERE request_id = ? AND org = ?", (request_id, org)).fetchone()
        if req is None:
            raise RequestError("Request not found.")
        if req["status"] != "OPEN":
            raise RequestError("The request is already closed.")
        task = conn.execute("SELECT status FROM request_tasks WHERE request_id = ? AND system = ?", (request_id, system)).fetchone()
        if task is None:
            raise RequestError("That request has no task for that system.")
        if task["status"] == "CONFIRMED":
            raise RequestError("That task is already confirmed.")
        now = datetime.now(timezone.utc)
        _event(store, org, request_id, "TASK_CONFIRMED", actor, now, system=system, reason=note)
        conn.execute("UPDATE request_tasks SET status = 'CONFIRMED', confirmed_by = ?, confirmed_at = ?, note = ? "
                     "WHERE request_id = ? AND system = ?", (actor, now.isoformat(), note, request_id, system))
        if all(t["status"] == "CONFIRMED" for t in _tasks(conn, request_id)):
            _close(store, conn, org, request_id, req["type"], actor, now, "all systems confirmed")
    return get_request(store, org, request_id)


def close_request(store, org: str, request_id: str, actor: str, reason: Optional[str] = None) -> dict:
    with store.writer() as conn:
        req = conn.execute("SELECT status, type FROM rights_requests WHERE request_id = ? AND org = ?", (request_id, org)).fetchone()
        if req is None:
            raise RequestError("Request not found.")
        if req["status"] != "OPEN":
            raise RequestError("The request is already closed.")
        if any(t["status"] != "CONFIRMED" for t in _tasks(conn, request_id)):
            raise RequestError("Every system's task must be confirmed before the request can be closed.")
        _close(store, conn, org, request_id, req["type"], actor, datetime.now(timezone.utc), (reason or "").strip()[:500] or None)
    return get_request(store, org, request_id)


def _close(store, conn, org: str, request_id: str, req_type: str, actor: str, now: datetime, reason: Optional[str]) -> None:
    _event(store, org, request_id, "CLOSED", actor, now, reason=reason)
    conn.execute("UPDATE rights_requests SET status = 'CLOSED', closed_at = ? WHERE request_id = ?", (now.isoformat(), request_id))
    if req_type == "erasure":      # from now on, seeing this identifier again is worth a finding
        conn.execute("""INSERT OR IGNORE INTO token_watchlist (org, key_id, token, request_id, added_at)
                        SELECT org, key_id, token, request_id, ? FROM request_tokens WHERE request_id = ?""",
                     (now.isoformat(), request_id))
        store.subjects.forget_watch(org)


# --------------------------------------------------------------------------- read

def get_request(store, org: str, request_id: str) -> dict:
    store.subjects.flush()
    with store._lock:
        c = store._conn
        r = c.execute("SELECT * FROM rights_requests WHERE request_id = ? AND org = ?", (request_id, org)).fetchone()
        if r is None:
            raise RequestError("Request not found.")
        events = [dict(e) for e in c.execute(
            "SELECT seq, row_hash, payload_json FROM evidence WHERE tenant_id = ? AND record_type = ? AND target_id = ? "
            "ORDER BY seq", (org, cn.RIGHTS_EVENT, request_id))]
        tasks = _tasks(c, request_id)
        watching = c.execute("SELECT COUNT(*) AS n FROM token_watchlist WHERE request_id = ?", (request_id,)).fetchone()["n"]
    for e in events:
        body = json.loads(decrypt_field(e.pop("payload_json")))
        e["action"], e["actor"], e["at"] = body["action"], body["actor"], body["at"]
    now = datetime.now(timezone.utc)
    due = datetime.fromisoformat(r["due_at"]) if r["due_at"] else None
    return {"request_id": r["request_id"], "org": r["org"], "type": r["type"], "status": r["status"],
            "received_at": r["received_at"], "due_at": r["due_at"], "closed_at": r["closed_at"],
            "overdue": bool(due and r["status"] == "OPEN" and now > due), "requester_ref": r["requester_ref"],
            "token_ref": r["token_ref"], "created_by": r["created_by"], "created_at": r["created_at"],
            "lookup": json.loads(r["lookup_json"]), "tasks": tasks, "events": events, "watching": watching > 0}


def list_requests(store, org: str, status: Optional[str] = None, limit: int = 200) -> List[dict]:
    with store._lock:
        q = "SELECT request_id FROM rights_requests WHERE org = ?" + (" AND status = ?" if status else "") + \
            " ORDER BY created_at DESC LIMIT ?"
        args = [org] + ([status.upper()] if status else []) + [max(1, min(limit, 500))]
        ids = [r["request_id"] for r in store._conn.execute(q, args)]
    out = []
    for i in ids:
        d = get_request(store, org, i)
        d["lookup"] = [{"category": x["category"], "systems": len(x["systems"])} for x in d["lookup"]]
        out.append(d)
    return out


# --------------------------------------------------------------------------- chain replay

def verify_event(signed: dict, state: Dict[str, dict]) -> bool:
    """One RIGHTS_EVENT during verify_chain. `state` maps request_id to {status, tasks (system -> confirmed) or None}."""
    rid, action = signed.get("request_id"), signed.get("action")
    if not rid:
        return False
    cur = state.get(rid)
    if action == "CREATED":
        if cur is not None or signed.get("request_type") not in TYPES:
            return False
        state[rid] = {"status": "OPEN", "tasks": None}
        return True
    if cur is None or cur["status"] != "OPEN":
        return False
    if action == "TASKS_CREATED":
        systems = signed.get("systems")
        if cur["tasks"] is not None or not isinstance(systems, list) or not all(isinstance(s, str) for s in systems):
            return False
        cur["tasks"] = {s: False for s in systems}
        return True
    if cur["tasks"] is None:
        return False
    if action == "TASK_CONFIRMED":
        system = signed.get("system")
        if system not in cur["tasks"] or cur["tasks"][system]:
            return False
        cur["tasks"][system] = True
        return True
    if action == "CLOSED":
        if not all(cur["tasks"].values()):
            return False
        cur["status"] = "CLOSED"
        return True
    return False
