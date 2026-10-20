"""
Builds the observed processing map (nodes, edges) and the record of observed processing from three sources:
the organization's declared fields, the counters of what was observed (evidence_store/flows.py) and the open incidents.

Colours (status of a system):
  red     an open incident exists for it (a violation somebody has not resolved)
  amber   a kind of personal data was observed there that its declared fields do not cover
  green   everything observed there is declared and nothing is open
  grey    declared, but nothing has been observed

What it cannot know is said in the payload: it shows what Veritas has seen in the logs it received since it began
counting, not every place personal data exists.
"""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from evidence_store import flows as flow_store

_WORDS = re.compile(r"[a-z0-9]+")
NOTE = ("Observed processing: what Veritas has seen in the logs it received since it began counting. "
        "It is not a complete map of where personal data exists, and it is not a statement of legal compliance.")


def _tokens(*names: str) -> set:
    out = set()
    for n in names:
        out.update(_WORDS.findall((n or "").lower()))
        out.add((n or "").lower())
    return out


def _open_incidents(store, tenant: str) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    with store._lock:
        rows = store._conn.execute(
            "SELECT incident_id, number, source_system, template, severity, count, status FROM incidents "
            "WHERE tenant_id = ? AND merged_into IS NULL AND status != 'RESOLVED' "
            "ORDER BY severity_rank DESC, count DESC", (tenant,)).fetchall()
    for r in rows:
        slot = out.setdefault(r["source_system"], {"total": 0, "top": []})
        slot["total"] += 1
        if len(slot["top"]) < 5:
            slot["top"].append({"incident_id": r["incident_id"], "number": r["number"], "template": r["template"],
                                "severity": r["severity"], "count": r["count"], "status": r["status"]})
    return out


def build(store, tenant: str, config=None) -> dict:
    observed = flow_store.rows(store, tenant)
    declared: Dict[str, list] = {}
    owners: Dict[str, dict] = {}
    if config is not None:
        for f in config.fields:
            declared.setdefault(f.source_system, []).append(f)
        owners = {k: v.model_dump() for k, v in (getattr(config, "owners", None) or {}).items()}
    open_inc = _open_incidents(store, tenant)
    systems = sorted(set(declared) | {o["source_system"] for o in observed})
    lower_systems = {s.lower(): s for s in systems}

    nodes, edges = [], {}
    for system in systems:
        fields = declared.get(system, [])
        cover = _tokens(*[x for f in fields for x in (f.pii_category, f.field_name)])
        seen: Dict[str, dict] = {}
        for o in (r for r in observed if r["source_system"] == system):
            c = seen.setdefault(o["category"], {"category": o["category"], "fields": set(), "kinds": set(), "count": 0,
                                                "first_seen": o["first_seen"], "last_seen": o["last_seen"]})
            c["fields"].add(o["field"])
            c["kinds"].add(o["source_kind"])
            c["count"] += o["count"]
            c["first_seen"] = min(c["first_seen"], o["first_seen"])
            c["last_seen"] = max(c["last_seen"], o["last_seen"])
            if o["destination"]:
                key = (system, o["destination"])
                e = edges.setdefault(key, {"source": system, "destination": o["destination"], "count": 0,
                                           "categories": {}, "first_seen": o["first_seen"], "last_seen": o["last_seen"]})
                e["count"] += o["count"]
                e["categories"][o["category"]] = e["categories"].get(o["category"], 0) + o["count"]
                e["first_seen"] = min(e["first_seen"], o["first_seen"])
                e["last_seen"] = max(e["last_seen"], o["last_seen"])
        observed_list = []
        undeclared = 0
        for c in sorted(seen.values(), key=lambda x: -x["count"]):
            is_declared = c["category"].lower() in cover
            undeclared += 0 if is_declared else 1
            observed_list.append({**c, "fields": sorted(c["fields"]), "kinds": sorted(c["kinds"]), "declared": is_declared})
        inc = open_inc.get(system, {"total": 0, "top": []})
        if inc["total"]:
            status = "red"
        elif undeclared:
            status = "amber"
        elif observed_list:
            status = "green"
        else:
            status = "grey"
        seen_fields = {f for c in observed_list for f in c["fields"]}
        nodes.append({
            "id": system, "status": status, "owner": owners.get(system),
            "declared": [{"field": f.field_name, "category": f.pii_category, "purpose": f.declared_purpose,
                          "consent_scope": f.consent_scope, "retention_days": f.retention_days,
                          "observed": f.field_name in seen_fields} for f in fields],
            "observed": observed_list,
            "open_incidents": inc["total"], "incidents": inc["top"],
            "events": sum(c["count"] for c in observed_list),
            "last_seen": max((c["last_seen"] for c in observed_list), default=None),
        })
    edge_list = []
    for e in sorted(edges.values(), key=lambda x: -x["count"]):
        internal = lower_systems.get(e["destination"].lower())
        e["target"] = internal or e["destination"]
        e["kind"] = "internal" if internal else "external"
        edge_list.append(e)
    return {
        "org": tenant, "generated_at": datetime.now(timezone.utc).isoformat(),
        "observing_since": min((o["first_seen"] for o in observed), default=None),
        "note": NOTE, "nodes": nodes, "edges": edge_list,
    }


# --------------------------------------------------------------------------- the record, as CSV

COLUMNS = ["record_type", "system", "field_or_destination", "data_category", "declared_purpose", "consent_scope",
           "retention_days", "declared", "observed", "observed_events", "first_seen", "last_seen", "open_incidents"]


def _cell(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def record_rows(flow_map: dict) -> List[dict]:
    rows = []
    for n in flow_map["nodes"]:
        by_field = {}
        for c in n["observed"]:
            for f in c["fields"]:
                by_field.setdefault(f, []).append(c)
        declared_fields = set()
        for d in n["declared"]:
            declared_fields.add(d["field"])
            hits = by_field.get(d["field"], [])
            rows.append({"record_type": "declared field", "system": n["id"], "field_or_destination": d["field"],
                         "data_category": d["category"], "declared_purpose": d["purpose"],
                         "consent_scope": d["consent_scope"], "retention_days": d["retention_days"],
                         "declared": "yes", "observed": "yes" if hits else "no",
                         "observed_events": sum(h["count"] for h in hits),
                         "first_seen": min((h["first_seen"] for h in hits), default=""),
                         "last_seen": max((h["last_seen"] for h in hits), default=""),
                         "open_incidents": n["open_incidents"]})
        for c in n["observed"]:
            if not c["declared"]:
                rows.append({"record_type": "observed, not declared", "system": n["id"],
                             "field_or_destination": ", ".join(c["fields"]), "data_category": c["category"],
                             "declared_purpose": "", "consent_scope": "", "retention_days": "", "declared": "no",
                             "observed": "yes", "observed_events": c["count"], "first_seen": c["first_seen"],
                             "last_seen": c["last_seen"], "open_incidents": n["open_incidents"]})
    for e in flow_map["edges"]:
        rows.append({"record_type": "destination (" + e["kind"] + ")", "system": e["source"],
                     "field_or_destination": e["target"], "data_category": ", ".join(sorted(e["categories"])),
                     "declared_purpose": "", "consent_scope": "", "retention_days": "", "declared": "",
                     "observed": "yes", "observed_events": e["count"], "first_seen": e["first_seen"],
                     "last_seen": e["last_seen"], "open_incidents": ""})
    return rows


def record_csv(flow_map: dict) -> str:
    out = io.StringIO()
    out.write("# Record of observed processing - " + flow_map["org"] + " - generated " + flow_map["generated_at"] + "\r\n")
    out.write("# " + flow_map["note"] + "\r\n")
    w = csv.writer(out)
    w.writerow(COLUMNS)
    for r in record_rows(flow_map):
        w.writerow([_cell(r[c]) for c in COLUMNS])
    return out.getvalue()
