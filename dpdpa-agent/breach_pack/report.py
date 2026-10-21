"""
A draft breach report for one incident: facts Veritas can vouch for (taken from the signed chain), and blank sections for
what only people know. It never carries a personal value, only counts, kinds of data, system and field names.

It is a starting point for the Data Protection Officer and counsel. It is not a filing, not legal advice, and the notification
deadlines and the content the Board and Data Principals must receive have to be confirmed against the Act and Rules by counsel.
"""
from __future__ import annotations

import csv
import io
import json
import zipfile
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db_encryption import decrypt_field
from evidence_store import canonical as cn

TO_COMPLETE = "TO COMPLETE BY THE DPO / COUNSEL"
LABELS = {
    "nature_of_the_breach": "Nature of the breach",
    "number_of_data_principals_affected": "Number of Data Principals affected",
    "likely_consequences": "Likely consequences",
    "measures_taken_and_planned": "Measures taken and planned",
    "contact_of_the_dpo": "Contact of the DPO",
    "date_and_time_the_organization_became_aware": "Date and time the organization became aware",
    "notified_data_principals": "Notified the Data Principals",
    "notified_the_board": "Notified the Board",
}


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _human(delta_seconds: Optional[float]) -> Optional[str]:
    if delta_seconds is None:
        return None
    s = int(max(0, delta_seconds))
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return (f"{d}d " if d else "") + (f"{h}h " if h or d else "") + f"{m}m"


def events_of(store, org: str, incident_id: str) -> List[Dict[str, Any]]:
    """The incident's chained events in order, with the sequence number of each (so each can be found in the audit pack)."""
    with store._lock:
        rows = store._conn.execute(
            "SELECT seq, payload_json FROM evidence WHERE tenant_id = ? AND record_type = ? AND target_id = ? ORDER BY row_index",
            (org, cn.INCIDENT_EVENT, incident_id)).fetchall()
    out = []
    for r in rows:
        b = json.loads(decrypt_field(r["payload_json"]))
        out.append({"seq": r["seq"], "at": b.get("at"), "action": b.get("action"), "from": b.get("old_status"),
                    "to": b.get("new_status"), "actor": b.get("actor"), "reason": b.get("reason")})
    return out


def kinds_of(store, org: str, incident_id: str, limit: int = 500) -> Dict[str, int]:
    """
    Kinds of personal data behind the incident, counted over its findings (names of kinds only). The finding's trace records the
    kind for every rule ("kind_of_data"); an older finding without a trace falls back to the stored registry entry.
    """
    counts: Counter = Counter()
    with store._lock:
        rows = store._conn.execute(
            "SELECT t.trace_json FROM verdict_trace t JOIN verdict_incident vi ON vi.verdict_id = t.verdict_id "
            "WHERE vi.tenant_id = ? AND vi.incident_id = ? LIMIT ?", (org, incident_id, limit)).fetchall()
    for r in rows:
        try:
            kind = (json.loads(r["trace_json"]).get("context") or {}).get("kind_of_data")
        except ValueError:
            kind = None
        if kind:
            counts[str(kind)] += 1
    if counts:
        return dict(counts)
    for v in store.incident_verdicts(org, incident_id, limit=limit) if hasattr(store, "incident_verdicts") else []:
        m = v.get("matched_registry_entry") or {}
        kind = (m.get("category") or m.get("pii_category")) if isinstance(m, dict) else None
        if kind:
            counts[str(kind)] += 1
    return dict(counts)


def gather(store, org: str, incident: Dict[str, Any], owner: Optional[Dict[str, Any]], policy_name: Optional[str] = None) -> Dict[str, Any]:
    iid = incident["incident_id"]
    events = events_of(store, org, iid)
    first, last = _parse(incident.get("first_seen")), _parse(incident.get("last_seen"))
    resolved = _parse(incident.get("resolved_at"))
    ack = next((e for e in events if e["action"] == "STATUS" and e["to"] == "ACKNOWLEDGED"), None)
    ack_at = _parse(ack["at"]) if ack else None
    head = store.chain_head(org)
    return {
        "organization": org,
        "generated_at": cn.rfc3339_ms(datetime.now(timezone.utc)),
        "incident": {"number": incident["number"], "id": iid, "rule": incident["rule_id"], "system": incident["source_system"],
                     "field": incident["field"], "severity": incident["severity"], "status": incident["status"],
                     "breach_candidate": incident.get("breach_candidate"), "findings": incident["count"],
                     "first_seen": incident.get("first_seen"), "last_seen": incident.get("last_seen"),
                     "resolved_at": incident.get("resolved_at"), "recurred_times": incident.get("recurred_count", 0),
                     "description": incident.get("hint")},
        "data_kinds": kinds_of(store, org, iid),
        "owner": owner,
        "durations": {"active_for": _human((last - first).total_seconds()) if first and last else None,
                      "to_acknowledge": _human((ack_at - first).total_seconds()) if ack_at and first else None,
                      "to_resolve": _human((resolved - first).total_seconds()) if resolved and first else None},
        "timeline": events,
        "chain": {"head_hash": head["head_hash"], "records": head["record_count"]},
        "to_complete": {k: TO_COMPLETE for k in (
            "nature_of_the_breach", "number_of_data_principals_affected", "likely_consequences", "measures_taken_and_planned",
            "contact_of_the_dpo", "date_and_time_the_organization_became_aware", "notified_data_principals", "notified_the_board")},
    }


def markdown(r: Dict[str, Any]) -> str:
    i = r["incident"]
    d = r["durations"]
    kinds = ", ".join(f"{k} ({n} finding{'s' if n != 1 else ''})" for k, n in sorted(r["data_kinds"].items())) or "not recorded in the findings"
    L = [
        f"# Draft breach report: incident #{i['number']}, {r['organization']}",
        "",
        f"Prepared {r['generated_at']} from Veritas's signed evidence chain. **Draft for the Data Protection Officer and counsel. "
        "Not a filing and not legal advice.** The deadlines for telling the Data Protection Board and the people affected, and what "
        "each notice must contain, are set by the Act and the Rules: have counsel confirm them before relying on this page.",
        "",
        "## What Veritas observed (taken from the chain)",
        f"- Rule: {i['rule']}; severity {i['severity']}; flagged as a possible breach: {'yes' if i['breach_candidate'] else 'no'}.",
        f"- Where: system `{i['system']}`, field `{i['field']}`.",
        f"- First seen {i['first_seen']}; last seen {i['last_seen']}; active for {d['active_for'] or 'unknown'}.",
        f"- Findings grouped in this incident: {i['findings']}. A finding is one sighting, not one person: this is **not** a count of people affected.",
        f"- Kinds of personal data involved: {kinds}.",
        f"- Came back after being resolved: {i['recurred_times']} time(s).",
        f"- Status now: {i['status']}" + (f", resolved {i['resolved_at']}" if i["resolved_at"] else "") + ".",
    ]
    if i.get("description"):
        L.append(f"- What the findings looked like: {i['description']}")
    L += ["", "## Response so far"]
    o = r["owner"]
    L.append(f"- Responsible owner of the system: {o.get('name') or o.get('team') or o}" if o else "- No owner is recorded for this system in the policy.")
    L += [f"- Time to acknowledge: {d['to_acknowledge'] or 'not acknowledged'}; time to resolve: {d['to_resolve'] or 'not resolved'}.", "", "## Timeline (each entry is a signed record in the chain)", "",
          "| Chain seq | When | Action | From | To | By | Reason |", "|---|---|---|---|---|---|---|"]
    for e in r["timeline"]:
        L.append(f"| {e['seq']} | {e['at']} | {e['action']} | {e['from'] or ''} | {e['to'] or ''} | {e['actor'] or ''} | {e['reason'] or ''} |")
    if not r["timeline"]:
        L.append("| | | no events yet | | | | |")
    L += ["", "## To be completed by people", "",
          "Veritas cannot know these. They are left blank on purpose.", ""]
    for k, v in r["to_complete"].items():
        L.append(f"- **{LABELS.get(k, k.replace('_', ' ').capitalize())}:** {v}")
    L += ["", "## How to check this", "",
          f"The chain head when this was prepared was `{r['chain']['head_hash']}` after {r['chain']['records']} records. "
          "Download the audit pack for the same organization and run the verifier to show these records are the signed ones.", ""]
    return "\n".join(L)


def timeline_csv(r: Dict[str, Any]) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["chain_seq", "at", "action", "from", "to", "actor", "reason"])
    for e in r["timeline"]:
        w.writerow([e["seq"], e["at"], e["action"], e["from"] or "", e["to"] or "", e["actor"] or "", e["reason"] or ""])
    return out.getvalue()


def build_zip(report: Dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("REPORT.md", markdown(report))
        z.writestr("report.json", json.dumps(report, indent=2, sort_keys=True, default=str))
        z.writestr("timeline.csv", timeline_csv(report))
    return buf.getvalue()
