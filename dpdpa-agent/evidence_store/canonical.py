"""
Canonical record format for the evidence chain (hash_version 1).

Why this exists. The original chain (hash_version 0) hashes whatever Python's `json.dumps` happens to produce,
which only Python can reproduce. An auditor's stand-alone verifier (written in Go) has to compute the same
bytes, so version 1 defines them exactly. Old records are never rehashed: they stay version 0 forever, and the
first version-1 record simply continues the chain from the last version-0 hash.

  hash_input  = "veritas-chain-v1" LF previous_hash LF canonical_json(record_body)
  record_hash = lowercase hex of SHA-256(hash_input as UTF-8)

Canonical JSON (the rules both implementations follow, byte for byte):
  * UTF-8, no whitespace outside strings;
  * object keys sorted by their UTF-8 bytes;
  * values are strings, integers, objects or arrays only: floats and booleans are not allowed (a record body
    holds 0/1 for a flag and a whole number for a fraction, see verdict_body);
  * a null (None) member is omitted;
  * strings: only `"` and `\\` are escaped with a backslash, control characters U+0000 to U+001F are written
    as \\u00xx with lowercase hex, and every other character is written as itself;
  * timestamps are RFC 3339 UTC with exactly three fractional digits and a Z.

The record body never contains `hash` or `previous_hash`; it names its own type, organization and position
(`seq`), so a record cannot be moved to another place or another organization without changing its hash.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

HASH_VERSION = 1
CHAIN_DOMAIN = "veritas-chain-v1"

VERDICT = "VERDICT"
STATUS_CHANGE = "STATUS_CHANGE"
COMMENT = "COMMENT"
INCIDENT_EVENT = "INCIDENT_EVENT"
RIGHTS_EVENT = "RIGHTS_EVENT"
RULE_EVENT = "RULE_EVENT"
RESTORE_EVENT = "RESTORE_EVENT"
RECORD_TYPES = (VERDICT, STATUS_CHANGE, COMMENT, INCIDENT_EVENT, RIGHTS_EVENT, RULE_EVENT, RESTORE_EVENT)


# --------------------------------------------------------------------------- canonical JSON

def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif c < 0x20:
            out.append("\\u%04x" % c)
        else:
            out.append(ch)
    out.append('"')
    text = "".join(out)
    text.encode("utf-8")          # a lone surrogate cannot be written: fail now, not at hash time
    return text


def canonical_json(value: Any) -> str:
    if value is None:
        raise TypeError("null is only allowed as an omitted object member")
    if isinstance(value, bool) or isinstance(value, float):
        raise TypeError(f"{type(value).__name__} is not allowed in a canonical record (use 0/1 or a whole number)")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, dict):
        members = []
        for key in sorted((k for k, v in value.items() if v is not None), key=lambda k: k.encode("utf-8")):
            if not isinstance(key, str):
                raise TypeError("object keys must be strings")
            members.append(_string(key) + ":" + canonical_json(value[key]))
        return "{" + ",".join(members) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    raise TypeError(f"{type(value).__name__} is not allowed in a canonical record")


def rfc3339_ms(moment: datetime) -> str:
    """RFC 3339 UTC with milliseconds and Z. A naive time is taken to be UTC."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (moment.microsecond // 1000)


# --------------------------------------------------------------------------- hashing

def v0_hash(payload_json: str, previous_hash: str) -> str:
    """The original chain: sha256(payload_json + previous_hash). Unchanged since the evidence store was built."""
    return hashlib.sha256((payload_json + previous_hash).encode("utf-8")).hexdigest()


def v1_hash(previous_hash: str, body: Dict[str, Any]) -> str:
    material = CHAIN_DOMAIN + "\n" + previous_hash + "\n" + canonical_json(body)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- record bodies

def verdict_body(ev, org: str, seq: int) -> Dict[str, Any]:
    """Body of a VERDICT record from an ExplainedVerdict."""
    v = ev.verdict
    return {
        "type": VERDICT, "org": org, "seq": seq,
        "verdict_id": str(v.verdict_id), "event_id": str(v.event_id),
        "rule_id": v.rule_id.value, "severity": v.severity.value, "source": v.source.value,
        "source_system": v.source_system, "field": v.field,
        "timestamp": rfc3339_ms(v.timestamp),
        "matched_registry_entry": v.matched_registry_entry,
        "breach_notification_candidate": 1 if v.breach_notification_candidate else 0,
        "explanation": ev.explanation, "section_cited": ev.section_cited,
        "confidence_permille": int(round(float(ev.confidence) * 1000)),
        "used_fallback": 1 if ev.used_fallback else 0,
    }


def status_change_body(org: str, seq: int, event_id: str, target: str, old: str, new: str,
                       actor: str, reason: Optional[str], at: datetime) -> Dict[str, Any]:
    return {"type": STATUS_CHANGE, "org": org, "seq": seq, "event_id": event_id, "target": target,
            "old_status": old, "new_status": new, "actor": actor, "reason": reason or None,
            "at": rfc3339_ms(at)}


def comment_body(org: str, seq: int, event_id: str, target: str, actor: str, text: str, at: datetime) -> Dict[str, Any]:
    """The text itself stays in case_comments; the chain holds its hash."""
    return {"type": COMMENT, "org": org, "seq": seq, "event_id": event_id, "target": target,
            "actor": actor, "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "at": rfc3339_ms(at)}


def incident_event_body(org: str, seq: int, event_id: str, incident_id: str, action: str, old: Optional[str],
                        new: Optional[str], actor: str, reason: Optional[str], at: datetime,
                        other_id: Optional[str] = None, moved: Optional[int] = None) -> Dict[str, Any]:
    """
    A change to an incident: STATUS (an analyst), RECUR (the system reopened a resolved incident), MERGE (`other_id`
    was folded into `incident_id`) or SPLIT (`moved` verdicts of `other_id` became `incident_id`). Only status
    changes are replayed by the verifier of the chain; merge and split are recorded so they cannot be denied.
    """
    return {"type": INCIDENT_EVENT, "org": org, "seq": seq, "event_id": event_id, "incident_id": incident_id,
            "action": action, "old_status": old, "new_status": new, "actor": actor, "reason": reason or None,
            "other_id": other_id, "moved": moved, "at": rfc3339_ms(at)}


def rights_event_body(org: str, seq: int, event_id: str, request_id: str, action: str, actor: str, at: datetime,
                      request_type: Optional[str] = None, systems: Optional[list] = None, system: Optional[str] = None,
                      identifiers: Optional[int] = None, reason: Optional[str] = None) -> Dict[str, Any]:
    """
    A step in a rights request: CREATED, TASKS_CREATED (one task per system in `systems`), TASK_CONFIRMED (`system`)
    or CLOSED. No identifier and no requester reference is in the record, only the request id and counts.
    """
    return {"type": RIGHTS_EVENT, "org": org, "seq": seq, "event_id": event_id, "request_id": request_id,
            "action": action, "actor": actor, "request_type": request_type, "systems": systems, "system": system,
            "identifiers": identifiers, "reason": reason or None, "at": rfc3339_ms(at)}


def rule_event_body(org: str, seq: int, event_id: str, change_id: str, action: str, actor: str, at: datetime,
                    kind: Optional[str] = None, target: Optional[str] = None, setting: Optional[dict] = None,
                    expires_at: Optional[str] = None, self_approved: Optional[int] = None,
                    reason: Optional[str] = None) -> Dict[str, Any]:
    """
    A step in a change to the rules in force: PROPOSED (carries what is proposed: `kind` OVERLAY or EXCEPTION, its `target`
    rule id and its `setting`), APPROVED (a second person, or the same one with `self_approved` 1 in a single-admin
    organization), REJECTED, WITHDRAWN, REVOKED or EXPIRED. It carries settings and reasons, never a value from data.
    """
    return {"type": RULE_EVENT, "org": org, "seq": seq, "event_id": event_id, "change_id": change_id, "action": action,
            "actor": actor, "kind": kind, "target": target, "setting": setting, "expires_at": expires_at,
            "self_approved": self_approved, "reason": reason or None, "at": rfc3339_ms(at)}


def restore_event_body(org: str, seq: int, event_id: str, backup: str, restored_at: datetime, records_before: int,
                       records_after: int, head_before: Optional[str], restored_away: list, at: datetime,
                       actor: Optional[str] = None) -> Dict[str, Any]:
    """
    A restore from a backup: the organization's data was rewound to the backup. It records which backup, how many records the
    live chain held before and after, the head it had before, and the numbers of the signed checkpoints that described the history
    that was set aside (`restored_away`). The verifier reads it to tell a recorded restore from tampering: those checkpoints are
    reported as history that a restore removed, not as a failure. It holds no personal data.
    """
    return {"type": RESTORE_EVENT, "org": org, "seq": seq, "event_id": event_id, "backup": backup,
            "restored_at": rfc3339_ms(restored_at), "records_before": int(records_before), "records_after": int(records_after),
            "head_before": head_before, "restored_away": [int(n) for n in restored_away], "actor": actor, "at": rfc3339_ms(at)}


def legacy_view(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    The shape the rest of the product reads (the version-0 field names and types), made from a version-1 body:
    `confidence` as a fraction, flags as booleans, and without the chain bookkeeping fields.
    """
    out = {k: v for k, v in body.items() if k not in ("type", "org", "seq", "confidence_permille")}
    out["tenant_id"] = body["org"]
    out["confidence"] = body["confidence_permille"] / 1000.0
    out["breach_notification_candidate"] = bool(body.get("breach_notification_candidate"))
    out["used_fallback"] = bool(body.get("used_fallback"))
    out.setdefault("matched_registry_entry", None)
    return out
