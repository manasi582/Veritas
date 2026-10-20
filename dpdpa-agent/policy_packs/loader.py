"""
Reads the policy packs and turns one into a policy for an organization.

A pack is data: fields with a purpose, scope and retention period (each with a note on why that value, for counsel), the systems
they sit in under generic names, linkage rules, suggested notices and things to watch for. Applying a pack:

  * renames the pack's generic systems to the organization's own (`system_map`); with a map, only the mapped systems are used;
  * adds only what the policy does not already hold: an existing field is never changed, a second apply adds nothing;
  * never creates a notice (a notice is a fact the organization must state: when it took effect), only suggests them;
  * checks the result with the same validator an upload uses.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from org_config.validator import validate_org_config
from runtime_paths import bundle_root

PACKS_DIR = bundle_root() / "policy_packs" / "packs"
UNREVIEWED = ("DRAFT",)


class PackError(ValueError):
    pass


def _load_all() -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for p in sorted(PACKS_DIR.glob("*.json")):
        data = json.loads(p.read_text(encoding="utf-8"))
        out[data["id"]] = data
    return out


def list_packs() -> List[dict]:
    return [{"id": p["id"], "title": p["title"], "industry": p["industry"], "version": p["version"], "status": p["status"],
             "reviewed_by": p.get("reviewed_by"), "reviewed_on": p.get("reviewed_on"), "summary": p["summary"],
             "systems": p["systems"], "fields": len(p["fields"])} for p in _load_all().values()]


def get_pack(pack_id: str) -> dict:
    packs = _load_all()
    if pack_id not in packs:
        raise PackError(f"No policy pack called {pack_id!r}.")
    return copy.deepcopy(packs[pack_id])


def _key(system: str, field: str) -> str:
    return f"{system.strip().lower()}|{field.strip().lower()}"


def merge(pack: dict, existing: Optional[dict], org_id: str, system_map: Optional[Dict[str, str]] = None,
          owners: Optional[Dict[str, dict]] = None) -> dict:
    """{"policy", "added", "skipped", "errors", "unreviewed", ...}: what applying the pack would do. Nothing is written."""
    system_map = {k: v.strip() for k, v in (system_map or {}).items() if isinstance(v, str) and v.strip()}
    unknown = sorted(set(system_map) - set(pack["systems"]))
    if unknown:
        raise PackError("Not systems of this pack: " + ", ".join(unknown))
    if len(set(system_map.values())) != len(system_map):
        raise PackError("Two pack systems cannot map to the same system of yours.")

    def target(system: str) -> Optional[str]:
        if not system_map:
            return system
        return system_map.get(system)

    policy = copy.deepcopy(existing) if existing else {"org_id": org_id, "fields": []}
    policy.setdefault("fields", [])
    have = {_key(f.get("source_system", ""), f.get("field_name", "")) for f in policy["fields"]}
    added: List[dict] = []
    skipped: List[dict] = []
    for f in pack["fields"]:
        system = target(f["source_system"])
        if system is None:
            continue
        if _key(system, f["field_name"]) in have:
            skipped.append({"system": system, "field": f["field_name"], "reason": "already in the policy; left as it is"})
            continue
        entry = {k: v for k, v in f.items() if k != "basis"}
        entry["source_system"] = system
        policy["fields"].append(entry)
        have.add(_key(system, f["field_name"]))
        added.append({"system": system, "field": f["field_name"], "category": f["pii_category"], "purpose": f["declared_purpose"],
                      "retention_days": f["retention_days"], "basis": f["basis"]})
    used_names = {a["field"].lower() for a in added} | {f["field_name"].lower() for f in policy["fields"]}
    rules = policy.setdefault("linkage_rules", [])
    seen = {tuple(sorted(r["fields"])) for r in rules}
    linkage_added = 0
    for r in pack.get("linkage_rules", []):
        if all(n.lower() in used_names for n in r["fields"]) and tuple(sorted(r["fields"])) not in seen:
            rules.append(copy.deepcopy(r))
            seen.add(tuple(sorted(r["fields"])))
            linkage_added += 1
    own = policy.setdefault("owners", {})
    owners_added = []
    for system, o in (owners or {}).items():
        if system not in own and any(a["system"] == system for a in added):
            own[system] = {k: v for k, v in o.items() if k in ("team", "email", "slack_channel") and v}
            owners_added.append(system)
    for k in ("linkage_rules", "owners"):
        if not policy.get(k):
            policy.pop(k, None)
    errors = validate_org_config(policy) if added or not existing else []
    mapped = lambda s: system_map.get(s, s) if system_map else s  # noqa: E731
    return {
        "pack": {"id": pack["id"], "version": pack["version"], "status": pack["status"], "reviewed_by": pack.get("reviewed_by")},
        "unreviewed": pack["status"] in UNREVIEWED, "review_note": pack["review_note"],
        "added": added, "skipped": skipped, "linkage_rules_added": linkage_added, "owners_added": owners_added,
        "notice_suggestions": [{**n, "systems": [mapped(s) for s in n["systems"] if not system_map or s in system_map]} for n in pack.get("notice_suggestions", [])],
        "watch_for": pack.get("watch_for", []),
        "errors": errors, "policy": policy,
        "note": "Nothing has been saved. Notices are not created by a pack: record each notice you have actually published, with its real date.",
    }
