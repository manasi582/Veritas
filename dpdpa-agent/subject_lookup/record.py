"""
The lookup and rights-request record: what was asked, where Veritas observed the identifier, who confirmed each system,
and which entries of the evidence chain the facts rest on. It is signed with Veritas's Ed25519 key (the one that signs
anchoring checkpoints): the signature covers the canonical JSON of the record, and the PDF prints the same signature,
so the PDF and the JSON can be checked against each other and against the public key.

It states what it is not: not a certificate of complete erasure.
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from anchoring import keys as signing_keys
from evidence_store import canonical as cn
from subject_lookup import pdf, rights

STATEMENTS = [
    "This record lists where Veritas observed the identifier(s) in the logs it received, and who confirmed each system. "
    "It is not a certificate that the data was erased everywhere.",
    "Veritas cannot see systems it receives no logs from, copies outside logs, backups, or data that was never logged.",
    "Veritas does not store the identifiers. This record shows only a short prefix of each keyed token.",
    "A due date appears only if one was entered or configured. Confirm the current response periods under the DPDPA "
    "Rules before relying on it.",
]


def build(store, org: str, request_id: str) -> dict:
    r = rights.get_request(store, org, request_id)
    with store._lock:
        head = store.chain_head(org)
    body = {
        "format": "veritas-rights-record-v1",
        "title": {"erasure": "Lookup and erasure record", "retention": "Retention review record"}.get(r["type"], "Lookup and rights request record"),
        "org": org, "request_id": r["request_id"], "type": r["type"], "status": r["status"],
        "requester_ref": r["requester_ref"], "received_at": r["received_at"], "due_at": r["due_at"],
        "closed_at": r["closed_at"], "generated_at": cn.rfc3339_ms(datetime.now(timezone.utc)),
        "identifiers": [{
            "category": x["category"], "token_prefix": x["token_prefix"],
            "systems": [{"system": s["system"], "events": s["events"], "first_seen": s["first_seen"],
                         "last_seen": s["last_seen"]} for s in x["systems"]],
            "linked_verdicts": [{"violation_id": v["violation_id"], "rule_id": v["rule_id"], "chain_seq": v["chain_seq"],
                                 "chain_hash": v["chain_hash"]} for v in x["verdicts"]],
        } for x in r["lookup"]],
        "tasks": [{"system": t["system"], "owner": t["owner"], "status": t["status"], "confirmed_by": t["confirmed_by"],
                   "confirmed_at": t["confirmed_at"], "note": t["note"]} for t in r["tasks"]],
        "chain": {"request_events": [{"seq": e["seq"], "action": e["action"], "chain_hash": e["row_hash"]} for e in r["events"]],
                  "head_seq": head["last_seq"], "head_hash": head["head_hash"]},
        "watch_list": "yes" if r["watching"] else "no",
        "statements": STATEMENTS + (["After closure the identifier is on a watch list; if it is observed again Veritas raises ERASURE_001."]
                                    if r["type"] == "erasure" else []),
    }
    return body


def sign(body: dict) -> dict:
    private, public_raw, key_id = signing_keys.load_or_create()
    message = cn.canonical_json(body).encode("utf-8")
    return {"alg": "Ed25519", "key_id": key_id, "public_key": base64.b64encode(public_raw).decode(),
            "signed": "sha256:" + hashlib.sha256(message).hexdigest(), "signature": private.sign(message).hex()}


def verify(body: dict, signature: dict) -> bool:
    """True if `signature` is a valid Ed25519 signature of the record's canonical JSON under the public key it names."""
    try:
        public_raw = base64.b64decode(signature["public_key"])
        return signing_keys.verify_signature(public_raw, cn.canonical_json(body).encode("utf-8"), signature["signature"])
    except Exception:
        return False


def to_pdf(body: dict, signature: dict) -> bytes:
    L: List[Tuple[str, str]] = []
    n = lambda text="": L.append(("n", text))
    h = lambda text: (L.append(("b", "")), L.append(("h", text)))
    n(f"Organisation: {body['org']}")
    n(f"Request: {body['request_id']}   Type: {body['type']}   Status: {body['status']}")
    n(f"Requester reference: {body['requester_ref']}")
    n(f"Received: {body['received_at']}   Due: {body['due_at'] or 'not set'}   Closed: {body['closed_at'] or 'not closed'}")
    n(f"Generated: {body['generated_at']}")
    h("What Veritas observed")
    for x in body["identifiers"]:
        n(f"{x['category']} (token prefix {x['token_prefix']}):")
        if not x["systems"]:
            n("  not observed in any system")
        for s in x["systems"]:
            n(f"  {s['system']}: {s['events']} event(s), first {s['first_seen'][:19]}, last {s['last_seen'][:19]}")
        for v in x["linked_verdicts"]:
            n(f"  finding #{v['violation_id']} {v['rule_id']} chain entry {v['chain_seq']} hash {v['chain_hash'][:16]}...")
    h("Tasks")
    if not body["tasks"]:
        n("No system was observed to hold the identifier, so no task was created.")
    for t in body["tasks"]:
        done = f"confirmed by {t['confirmed_by']} at {(t['confirmed_at'] or '')[:19]}" if t["status"] == "CONFIRMED" else "open"
        n(f"{t['system']} (owner: {t['owner']}): {done}" + (f" - {t['note']}" if t["note"] else ""))
    h("Evidence chain entries")
    for e in body["chain"]["request_events"]:
        n(f"entry {e['seq']} {e['action']} hash {e['chain_hash']}")
    n(f"Chain head at generation: entry {body['chain']['head_seq']} hash {body['chain']['head_hash']}")
    n(f"Watch list after closure: {body['watch_list']}")
    h("What this record is and is not")
    for s in body["statements"]:
        n("- " + s)
    h("Signature")
    n(f"Algorithm: {signature['alg']}   Key id: {signature['key_id']}")
    n(f"Signed content: {signature['signed']}")
    n("Signature (hex, two lines; join them):")
    n(signature["signature"][:64])
    n(signature["signature"][64:])
    n("Public key (base64): " + signature["public_key"])
    n("The signature covers the canonical JSON of this record (GET .../record.json). See docs/SUBJECT_LOOKUP.md.")
    return pdf.render(body["title"], L)
