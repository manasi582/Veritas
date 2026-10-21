"""
Changes to the rules in force: overlays (severity, actions) and exceptions (a bounded, expiring suppression).

Every change is proposed by one person and approved by another (a single-administrator organization may approve its own,
and that is recorded as `self_approved`). Each step is a RULE_EVENT in the evidence chain, so a rule can never change quietly:
the verifier replays the events and compares them with these tables (a status that disagrees is STATUS_CACHE_MISMATCH).

Guardrails, all enforced here or in apply.py:
  * a core rule cannot be switched off (there is no such setting);
  * a severity can be lowered only to the floor of the finding's kind (Aadhaar, PAN, card, passport, voter stay HIGH);
  * an exception names a rule, has a reason and an owner, and ends on a date no more than VERITAS_EXCEPTION_MAX_DAYS away
    (default 180); there is no permanent suppression;
  * a finding that is a possible breach candidate is never suppressed by an exception.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import threading
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from evidence_store import canonical as cn
from rulebook import specs

OVERLAY, EXCEPTION = "OVERLAY", "EXCEPTION"
PROPOSED, APPROVED, REJECTED, WITHDRAWN, REVOKED, EXPIRED = "PROPOSED", "APPROVED", "REJECTED", "WITHDRAWN", "REVOKED", "EXPIRED"
REDACT_MODES = ("mask", "hash", "drop")
_KIND = re.compile(r"^[a-z][a-z0-9_]{1,30}$")
_PATTERN = re.compile(r"^[A-Za-z0-9_.*\[\]\-/: ]{1,200}$")
CACHE_SECONDS = 5


class ChangeError(ValueError):
    pass


def max_exception_days() -> int:
    try:
        return max(1, min(int(os.environ.get("VERITAS_EXCEPTION_MAX_DAYS", "180")), 3650))
    except ValueError:
        return 180


def create_tables(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rule_changes (
            change_id TEXT PRIMARY KEY, org TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL, setting_json TEXT NOT NULL,
            status TEXT NOT NULL, proposed_by TEXT NOT NULL, proposed_at TEXT NOT NULL, proposed_reason TEXT,
            decided_by TEXT, decided_at TEXT, decision_reason TEXT, self_approved INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT, number INTEGER NOT NULL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rule_changes_org ON rule_changes(org, status)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_changes_number ON rule_changes(org, number)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rule_exception_hits (
            org TEXT NOT NULL, change_id TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (org, change_id, day))""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS verdict_trace (
            verdict_id TEXT PRIMARY KEY, org TEXT NOT NULL, rule_version INTEGER NOT NULL, trace_json TEXT NOT NULL)""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rule_reviews (
            org TEXT NOT NULL, incident_id TEXT NOT NULL, request_id TEXT NOT NULL, PRIMARY KEY (org, incident_id))""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rule_escalations (
            org TEXT NOT NULL, incident_id TEXT NOT NULL, escalated_at TEXT NOT NULL, PRIMARY KEY (org, incident_id))""")


# --------------------------------------------------------------------------- validation

def _text(value: Any, what: str, lo: int, hi: int) -> str:
    v = str(value or "").strip()
    if not lo <= len(v) <= hi:
        raise ChangeError(f"{what} must be {lo} to {hi} characters.")
    return v


def _overlay(rule_id: str, setting: dict) -> dict:
    if rule_id not in specs.SPECS:
        raise ChangeError(f"Unknown rule {rule_id!r}.")
    unknown = set(setting) - {"severity", "actions", "escalate_after_minutes", "redact_kinds"}
    if unknown:
        raise ChangeError("Not settings of a rule: " + ", ".join(sorted(unknown)) + ". A core rule cannot be switched off.")
    out: Dict[str, Any] = {}
    sev = setting.get("severity")
    if sev is not None:
        sev = str(sev).upper()
        if sev not in specs.SEVERITIES:
            raise ChangeError("severity must be LOW, MEDIUM, HIGH or empty (the rule's own).")
        out["severity"] = sev
    actions = setting.get("actions", ["alert"])
    if not isinstance(actions, list) or not actions or any(a not in specs.ACTIONS for a in actions):
        raise ChangeError("actions must be a list drawn from: " + ", ".join(specs.ACTIONS) + ". There is no block action.")
    out["actions"] = sorted(set(actions), key=specs.ACTIONS.index)
    if "escalate" in out["actions"]:
        try:
            minutes = int(setting.get("escalate_after_minutes", 60))
        except (TypeError, ValueError):
            raise ChangeError("escalate_after_minutes must be a whole number of minutes.")
        if not 15 <= minutes <= 10080:
            raise ChangeError("escalate_after_minutes must be from 15 to 10080.")
        out["escalate_after_minutes"] = minutes
    kinds = setting.get("redact_kinds") or {}
    if "redact" in out["actions"]:
        if not isinstance(kinds, dict) or not kinds:
            raise ChangeError("the redact action needs redact_kinds, for example {\"aadhaar\": \"mask\"}.")
        for k, mode in kinds.items():
            if not _KIND.match(str(k)) or mode not in REDACT_MODES:
                raise ChangeError(f"redact_kinds: {k!r}: {mode!r}: use a kind of data and one of {', '.join(REDACT_MODES)}.")
        out["redact_kinds"] = {str(k).lower(): v for k, v in kinds.items()}
    elif kinds:
        raise ChangeError("redact_kinds is only for the redact action.")
    return out


def _exception(setting: dict, today: date) -> Tuple[str, dict]:
    unknown = set(setting) - {"rule_id", "system", "field", "reason", "ticket", "owner", "expires_at"}
    if unknown:
        raise ChangeError("Not settings of an exception: " + ", ".join(sorted(unknown)) + ".")
    rule_id = str(setting.get("rule_id") or "")
    if rule_id not in specs.SPECS:
        raise ChangeError("An exception names the rule it covers.")
    system = _text(setting.get("system") or "*", "system", 1, 200)
    field = _text(setting.get("field") or "*", "field", 1, 200)
    for what, v in (("system", system), ("field", field)):
        if not _PATTERN.match(v):
            raise ChangeError(f"{what} may use letters, digits, . _ - / : [ ] and * only.")
    if system == "*" and field == "*":
        raise ChangeError("An exception must narrow to a system or a field; it cannot cover everything.")
    try:
        ends = date.fromisoformat(str(setting.get("expires_at") or "")[:10])
    except ValueError:
        raise ChangeError("expires_at is a date (YYYY-MM-DD). An exception always ends.")
    if ends <= today:
        raise ChangeError("expires_at must be in the future.")
    if (ends - today).days > max_exception_days():
        raise ChangeError(f"An exception can last at most {max_exception_days()} days.")
    out = {"rule_id": rule_id, "system": system, "field": field, "reason": _text(setting.get("reason"), "reason", 10, 500),
           "owner": _text(setting.get("owner"), "owner", 2, 200), "expires_at": ends.isoformat()}
    if setting.get("ticket"):
        out["ticket"] = _text(setting["ticket"], "ticket", 1, 100)
    return rule_id, out


# --------------------------------------------------------------------------- events and rows

def _event(store, org: str, change_id: str, action: str, actor: str, at: datetime, **kw) -> None:
    store._append_event(org, cn.RULE_EVENT, change_id,
                        lambda event_id, seq: cn.rule_event_body(org, seq, event_id, change_id, action, actor, at, **kw))


def _row(r) -> dict:
    d = dict(r)
    d["setting"] = json.loads(d.pop("setting_json"))
    d["self_approved"] = bool(d["self_approved"])
    return d


def get(store, org: str, change_id: str) -> dict:
    with store._lock:
        r = store._conn.execute("SELECT * FROM rule_changes WHERE org = ? AND change_id = ?", (org, change_id)).fetchone()
    if r is None:
        raise ChangeError("Change not found.")
    return _row(r)


def list_changes(store, org: str, status: Optional[str] = None, kind: Optional[str] = None, limit: int = 200) -> List[dict]:
    where, args = ["org = ?"], [org]
    if status:
        where.append("status = ?"); args.append(status.upper())
    if kind:
        where.append("kind = ?"); args.append(kind.upper())
    with store._lock:
        rows = store._conn.execute(f"SELECT * FROM rule_changes WHERE {' AND '.join(where)} ORDER BY number DESC LIMIT ?",
                                   (*args, max(1, min(limit, 500)))).fetchall()
    return [_row(r) for r in rows]


# --------------------------------------------------------------------------- the steps

def propose(store, org: str, kind: str, setting: dict, actor: str, reason: Optional[str] = None,
            target: Optional[str] = None, now: Optional[datetime] = None) -> dict:
    now = now or datetime.now(timezone.utc)
    kind = (kind or "").upper()
    reason = (reason or "").strip()[:500] or None
    if kind == OVERLAY:
        target = str(target or "")
        setting = _overlay(target, setting or {})
        expires = None
    elif kind == EXCEPTION:
        target, setting = _exception(setting or {}, now.date())
        expires = setting["expires_at"]
    else:
        raise ChangeError("kind is OVERLAY or EXCEPTION.")
    change_id = str(uuid.uuid4())
    with store.writer() as conn:
        n = (conn.execute("SELECT COALESCE(MAX(number), 0) + 1 AS n FROM rule_changes WHERE org = ?", (org,)).fetchone()["n"])
        conn.execute("""INSERT INTO rule_changes (change_id, org, kind, target, setting_json, status, proposed_by, proposed_at,
                        proposed_reason, expires_at, number) VALUES (?, ?, ?, ?, ?, 'PROPOSED', ?, ?, ?, ?, ?)""",
                     (change_id, org, kind, target, json.dumps(setting, sort_keys=True), actor, now.isoformat(), reason, expires, n))
        _event(store, org, change_id, "PROPOSED", actor, now, kind=kind, target=target, setting=setting, expires_at=expires, reason=reason)
    invalidate(org)
    return get(store, org, change_id)


def _open(store, org: str, change_id: str) -> dict:
    c = get(store, org, change_id)
    if c["status"] != PROPOSED:
        raise ChangeError(f"This change is already {c['status'].lower()}.")
    return c


def approve(store, org: str, change_id: str, actor: str, reason: Optional[str] = None, self_approval_allowed: bool = False,
            now: Optional[datetime] = None) -> dict:
    now = now or datetime.now(timezone.utc)
    c = _open(store, org, change_id)
    same = c["proposed_by"] == actor
    if same and not self_approval_allowed:
        raise ChangeError("A different administrator must approve this change.")
    if c["kind"] == EXCEPTION and date.fromisoformat(c["expires_at"]) <= now.date():
        raise ChangeError("This exception's end date has passed; propose it again.")
    with store.writer() as conn:
        conn.execute("UPDATE rule_changes SET status = 'APPROVED', decided_by = ?, decided_at = ?, decision_reason = ?, self_approved = ? "
                     "WHERE change_id = ?", (actor, now.isoformat(), (reason or "")[:500] or None, int(same), change_id))
        _event(store, org, change_id, "APPROVED", actor, now, self_approved=int(same), reason=reason)
    invalidate(org)
    return get(store, org, change_id)


def _decide(store, org: str, change_id: str, actor: str, action: str, status: str, reason: Optional[str], now: Optional[datetime]) -> dict:
    now = now or datetime.now(timezone.utc)
    with store.writer() as conn:
        conn.execute("UPDATE rule_changes SET status = ?, decided_by = ?, decided_at = ?, decision_reason = ? WHERE change_id = ?",
                     (status, actor, now.isoformat(), (reason or "")[:500] or None, change_id))
        _event(store, org, change_id, action, actor, now, reason=reason)
    invalidate(org)
    return get(store, org, change_id)


def reject(store, org: str, change_id: str, actor: str, reason: Optional[str] = None, now: Optional[datetime] = None) -> dict:
    _open(store, org, change_id)
    return _decide(store, org, change_id, actor, "REJECTED", REJECTED, reason, now)


def withdraw(store, org: str, change_id: str, actor: str, reason: Optional[str] = None, now: Optional[datetime] = None) -> dict:
    c = _open(store, org, change_id)
    if c["proposed_by"] != actor:
        raise ChangeError("Only the person who proposed a change can withdraw it.")
    return _decide(store, org, change_id, actor, "WITHDRAWN", WITHDRAWN, reason, now)


def revoke(store, org: str, change_id: str, actor: str, reason: Optional[str] = None, now: Optional[datetime] = None) -> dict:
    """End an approved exception early. Ending one only tightens, so one person may do it. An overlay is changed by a new proposal."""
    c = get(store, org, change_id)
    if c["kind"] != EXCEPTION or c["status"] != APPROVED:
        raise ChangeError("Only an approved exception can be revoked. Change an overlay by proposing a new one.")
    return _decide(store, org, change_id, actor, "REVOKED", REVOKED, reason, now)


def expire_due(store, org: str, now: Optional[datetime] = None) -> int:
    now = now or datetime.now(timezone.utc)
    due = [c for c in list_changes(store, org, status=APPROVED, kind=EXCEPTION) if date.fromisoformat(c["expires_at"]) <= now.date()]
    for c in due:
        _decide(store, org, c["change_id"], "system", "EXPIRED", EXPIRED, "the end date passed", now)
    return len(due)


# --------------------------------------------------------------------------- replay (verify_chain)

def verify_event(signed: dict, state: Dict[str, dict]) -> bool:
    """One RULE_EVENT during verify_chain. `state` maps change_id to {status, kind, proposer}."""
    cid, action = signed.get("change_id"), signed.get("action")
    if not cid:
        return False
    cur = state.get(cid)
    if action == "PROPOSED":
        if cur is not None or signed.get("kind") not in (OVERLAY, EXCEPTION) or not isinstance(signed.get("setting"), dict) or not signed.get("target"):
            return False
        state[cid] = {"status": PROPOSED, "kind": signed["kind"], "proposer": signed.get("actor")}
        return True
    if cur is None:
        return False
    if action == "APPROVED":
        if cur["status"] != PROPOSED or bool(signed.get("self_approved")) != (signed.get("actor") == cur["proposer"]):
            return False
        cur["status"] = APPROVED
        return True
    if action in ("REJECTED", "WITHDRAWN"):
        if cur["status"] != PROPOSED or (action == "WITHDRAWN" and signed.get("actor") != cur["proposer"]):
            return False
        cur["status"] = action
        return True
    if action in ("REVOKED", "EXPIRED"):
        if cur["status"] != APPROVED or cur["kind"] != EXCEPTION:
            return False
        cur["status"] = action
        return True
    return False


# --------------------------------------------------------------------------- what is in force

class Active:
    def __init__(self, overlays: Dict[str, dict], exceptions: List[dict]):
        self.overlays = overlays
        self.exceptions = exceptions

    def exception_for(self, rule_id: str, system: str, field: str, today: date) -> Optional[dict]:
        for e in self.exceptions:
            s = e["setting"]
            # names and fields are compared ignoring case: an exception only narrows, so being forgiving here cannot widen it,
            # and a scope typed as "Raw_snippet" must not silently match nothing
            if (s["rule_id"] == rule_id and fnmatch.fnmatchcase(system.lower(), s["system"].lower())
                    and fnmatch.fnmatchcase(field.lower(), s["field"].lower())
                    and date.fromisoformat(s["expires_at"]) > today):
                return e
        return None


_cache: Dict[str, Tuple[float, Active]] = {}
_cache_lock = threading.Lock()


def invalidate(org: Optional[str] = None) -> None:
    with _cache_lock:
        if org is None:
            _cache.clear()
        else:
            _cache.pop(org, None)


def active(store, org: str) -> Active:
    with _cache_lock:
        hit = _cache.get(org)
        if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
            return hit[1]
    overlays: Dict[str, dict] = {}
    for c in reversed(list_changes(store, org, status=APPROVED, kind=OVERLAY, limit=500)):   # oldest first: the newest approved wins
        overlays[c["target"]] = c["setting"]
    exceptions = list_changes(store, org, status=APPROVED, kind=EXCEPTION, limit=500)
    a = Active(overlays, exceptions)
    with _cache_lock:
        _cache[org] = (time.monotonic(), a)
    return a


def count_exception_hit(store, org: str, change_id: str, day: Optional[str] = None) -> None:
    day = day or datetime.now(timezone.utc).date().isoformat()
    with store.writer() as conn:
        conn.execute("""INSERT INTO rule_exception_hits (org, change_id, day, n) VALUES (?, ?, ?, 1)
                        ON CONFLICT(org, change_id, day) DO UPDATE SET n = n + 1""", (org, change_id, day))


def exception_hits(store, org: str) -> Dict[str, int]:
    with store._lock:
        return {r["change_id"]: r["n"] for r in store._conn.execute(
            "SELECT change_id, SUM(n) AS n FROM rule_exception_hits WHERE org = ? GROUP BY change_id", (org,))}
