"""
Builds the audit pack for one organization.

Contents (all produced from what the server already keeps; nothing new is stored):
  evidence.jsonl      the whole chain, as `GET /v1/{org}/evidence/export`
  checkpoints.jsonl   the signed checkpoints, as `GET /v1/{org}/anchors/export`
  veritas.pub         the public key that verifies them
  summary.json        the same facts as SUMMARY.md, for machines
  SUMMARY.md          one page in plain words: the chain, the checks, what is open, what the pack does not prove
  VERIFY.md           how to check the pack on a machine with no Veritas and no network
  verify.sh/.bat      run the stand-alone verifier against the files above
  veritas-verify*     the verifier binaries, only if VERITAS_VERIFIER_DIR names a folder that holds them
  MANIFEST.sha256     a hash of every other file, so a changed file is noticed

The summary quotes counts and names of systems, never a personal value.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from anchoring import checkpoints as anchor_cps
from anchoring import export as anchor_export
from evidence_store import canonical as cn

logger = logging.getLogger("audit_pack")

PACK_VERSION = 1
MAX_BYTES_IN_MEMORY = 16 * 1024 * 1024


def _guard(label: str, fn, default):
    """A part of the summary that cannot be produced is marked as such; it never stops the pack."""
    try:
        return fn()
    except Exception:
        logger.debug("audit pack: %s unavailable", label, exc_info=True)
        return default


def gather(store, org: str, policy=None) -> Dict[str, Any]:
    head = store.chain_head(org)
    chain = _guard("chain check", lambda: store.verify_chain_detail(org), {"valid": None, "reason": "not checked"})
    manager = anchor_cps.get_manager()
    anchors = _guard("anchors", lambda: manager.status(org) if manager else {"enabled": False}, {"enabled": False})
    checkpoints = _guard("checkpoints", lambda: len(list(manager.all_checkpoints(org))) if manager else 0, 0)
    incidents = _guard("incidents", lambda: store.incident_summary(org), None)
    open_items: List[Dict[str, Any]] = []
    if incidents:
        for status in ("OPEN", "ACKNOWLEDGED"):
            found = _guard("open incidents", lambda st=status: store.list_incidents(org, status=st, limit=50), None)
            for r in (found[0] if found else []):
                open_items.append({"number": r.get("number"), "rule": r.get("rule_id"), "system": r.get("source_system"),
                                   "severity": r.get("severity"), "status": r.get("status"), "count": r.get("count"),
                                   "first_seen": r.get("first_seen"), "breach_candidate": r.get("breach_candidate")})
    retention = None
    notices = None
    if policy is not None:
        from retention_review import review as retention_review
        from notice_registry import coverage as notice_coverage
        retention = _guard("retention", lambda: retention_review.review(store, org, policy), None)
        notices = _guard("notices", lambda: notice_coverage.review(store, org, policy), None)
    def rules_summary():
        from rulebook import changes
        all_changes = changes.list_changes(store, org, limit=500)
        in_force = changes.active(store, org)
        return {"overlays_in_force": {k: v for k, v in in_force.overlays.items()},
                "exceptions_in_force": len(in_force.exceptions), "changes_recorded": len(all_changes),
                "pending": sum(1 for c in all_changes if c["status"] == changes.PROPOSED),
                "self_approved": sum(1 for c in all_changes if c["self_approved"])}
    rules = _guard("rules", rules_summary, None)
    return {
        "pack_version": PACK_VERSION,
        "organization": org,
        "generated_at": cn.rfc3339_ms(datetime.now(timezone.utc)),
        "chain": {"records": head["record_count"], "last_seq": head["last_seq"], "head_hash": head["head_hash"],
                  "internal_check": {"valid": chain.get("valid"), "reason": chain.get("reason")}},
        "anchoring": {"status": anchors, "checkpoints": checkpoints},
        "incidents": incidents,
        "open_incidents": open_items[:100],
        "retention": ({"counts": retention.get("summary")} if isinstance(retention, dict) else None),
        "notices": ({"counts": notices.get("summary")} if isinstance(notices, dict) else None),
        "rules": rules,
    }


def summary_markdown(s: Dict[str, Any]) -> str:
    c = s["chain"]
    ok = c["internal_check"]["valid"]
    inc = s.get("incidents") or {}
    lines = [
        f"# Audit pack summary: {s['organization']}",
        "",
        f"Produced {s['generated_at']} by Veritas. Read VERIFY.md first: check the evidence yourself before you rely on this page.",
        "",
        "## The evidence chain",
        f"- Records: {c['records']} (last sequence number {c['last_seq']}).",
        f"- Head hash: `{c['head_hash']}`",
        f"- Server's own check just now: {'passed' if ok else ('FAILED: ' + str(c['internal_check']['reason']) if ok is False else 'not run')}. "
        "This is the server marking its own homework; the independent check is the verifier.",
        f"- Signed checkpoints in the pack: {s['anchoring']['checkpoints']}"
        + ("" if s["anchoring"]["checkpoints"] else " (anchoring is not configured, so there is nothing for the verifier to compare against)") + ".",
        "",
        "## Findings",
    ]
    if inc:
        by = inc.get("by_status", {})
        lines += [f"- {inc.get('verdicts', 0)} verdicts grouped into {inc.get('incidents', 0)} incidents "
                  f"({by.get('OPEN', 0)} open, {by.get('ACKNOWLEDGED', 0)} acknowledged, {by.get('RESOLVED', 0)} resolved); "
                  f"{inc.get('recurred', 0)} came back after being resolved."]
    else:
        lines += ["- Incident summary unavailable."]
    if s["open_incidents"]:
        lines += ["", "Still open or acknowledged:", "", "| # | Rule | System | Severity | Status | Count | First seen |", "|---|---|---|---|---|---|---|"]
        for i in s["open_incidents"][:25]:
            lines.append(f"| {i['number']} | {i['rule']} | {i['system']} | {i['severity']} | {i['status']} | {i['count']} | {i['first_seen']} |")
    if s.get("retention"):
        lines += ["", "## Retention", f"- {json.dumps(s['retention'].get('counts'), sort_keys=True)}"]
    if s.get("notices"):
        lines += ["", "## Notices", f"- {json.dumps(s['notices'].get('counts'), sort_keys=True)}"]
    r = s.get("rules")
    if r is not None:
        lines += ["", "## Rules in force",
                  f"- {len(r['overlays_in_force'])} approved setting(s) on the six core rules, {r['exceptions_in_force']} exception(s) in force, "
                  f"{r['pending']} change(s) awaiting approval.",
                  f"- {r['changes_recorded']} change(s) recorded in the chain (each is a signed record: who proposed, who approved, when); "
                  f"{r['self_approved']} approved by the person who proposed it (allowed only for a single-administrator organization)."]
        for rule_id, o in sorted(r["overlays_in_force"].items()):
            lines.append(f"  - {rule_id}: {json.dumps(o, sort_keys=True)}")
    lines += [
        "",
        "## What this pack does not prove",
        "- It proves that these records have not been changed or removed since the last signed checkpoint. It does not prove the systems were free of other personal-data handling that Veritas never saw.",
        "- Records written after the last checkpoint are not covered by a signature.",
        "- Detection is probabilistic. A finding is evidence that something looked like personal data, not a legal finding.",
        "- Nothing here is legal advice or a statement that the organization complies with the Digital Personal Data Protection Act, 2023.",
        "",
    ]
    return "\n".join(lines)


VERIFY_MD = """# Checking this pack

You need nothing from Veritas except the files in this folder and the small verifier program. No server, no network (apart from
downloading the verifier once, if it is not already in this folder).

0. **The verifier.** If a file named `veritas-verify` (or `veritas-verify.exe`, or `veritas-verify_<version>_<system>`) is in this folder, use it.
   Otherwise download the one for your system from the release this pack was made by (Veritas __VERSION__) and check it against the
   signed `SHA256SUMS` in the same release:

   __DOWNLOADS__

   The verifier is about 600 lines of Go with no dependencies; you can also build it yourself from `tools/veritas-verify` in the source and
   trust nothing we hand you. Put it in this folder as `veritas-verify` and make it executable (`chmod +x veritas-verify`).
1. Check the files were not changed since the pack was made:
   - macOS / Linux: `shasum -a 256 -c MANIFEST.sha256`   (or `sha256sum -c MANIFEST.sha256`)
   - Windows (PowerShell): compare `Get-FileHash <file>` with the line for that file in MANIFEST.sha256
   This only shows the folder is as it left Veritas. Step 2 is the real check.
2. Run the independent verifier:
   - macOS / Linux: `./verify.sh`
   - Windows: `verify.bat`
   It reads evidence.jsonl, checkpoints.jsonl and veritas.pub and prints PASS or the first problem.
3. For a stronger check, take the checkpoints to a copy kept somewhere the server cannot reach
   (the file, syslog, e-mail or timestamp-authority witness described in docs/ANCHORING.md) and compare:
   `veritas-verify --evidence evidence.jsonl --checkpoints checkpoints.jsonl --pubkey veritas.pub --witness-dir <the witness folder>`.

Exit code 0 means PASS, 1 means the evidence does not match its checkpoints, 2 means a file was missing or unreadable.
A line `RESTORED_HISTORY` is information, not a failure: it means the evidence records a restore from a backup and names the checkpoints
that described the history it set aside. Compare it with your change records.
The formats are in docs/EVIDENCE_FORMAT.md.
"""

RELEASE_URL = "https://github.com/shreyaaassss/Veritas/releases/download/v{v}/veritas-verify_{v}_{target}"
VERIFIER_TARGETS = (("macOS, Apple silicon", "darwin_arm64"), ("Linux, 64-bit Intel/AMD", "linux_amd64"),
                    ("Linux, ARM", "linux_arm64"), ("Windows, 64-bit", "windows_amd64.exe"))


def verify_md() -> str:
    try:
        from veritas_version import get_version
        v = str(get_version()).lstrip("v")
    except Exception:
        v = ""
    if not v or v == "dev" or v == "unknown":
        return VERIFY_MD.replace("(Veritas __VERSION__) ", "").replace("__DOWNLOADS__",
               "the latest release at https://github.com/shreyaaassss/Veritas/releases (files named `veritas-verify_<version>_<system>`)")
    lines = "\n   ".join(f"- {label}: {RELEASE_URL.format(v=v, target=t)}" for label, t in VERIFIER_TARGETS)
    return VERIFY_MD.replace("__VERSION__", v).replace("__DOWNLOADS__", lines)


VERIFY_SH = """#!/bin/sh
# Runs the stand-alone verifier on this pack.
cd "$(dirname "$0")" || exit 2
V=""
for c in ./veritas-verify ./veritas-verify_*; do [ -x "$c" ] && V="$c" && break; done
[ -z "$V" ] && V="$(command -v veritas-verify)"
[ -z "$V" ] && { echo "veritas-verify not found. See VERIFY.md."; exit 2; }
exec "$V" --evidence evidence.jsonl --checkpoints checkpoints.jsonl --pubkey veritas.pub
"""

VERIFY_BAT = """@echo off
cd /d "%~dp0"
set V=
if exist veritas-verify.exe set V=veritas-verify.exe
if "%V%"=="" for %%f in (veritas-verify_*windows*.exe) do set V=%%f
if "%V%"=="" ( echo veritas-verify.exe not found. See VERIFY.md. & exit /b 2 )
%V% --evidence evidence.jsonl --checkpoints checkpoints.jsonl --pubkey veritas.pub
"""


def _verifier_files() -> List[Path]:
    """The verifier binaries to put in the pack: the folder VERITAS_VERIFIER_DIR names, else a `verifier` folder shipped with the install."""
    folders = []
    if os.environ.get("VERITAS_VERIFIER_DIR"):
        folders.append(Path(os.environ["VERITAS_VERIFIER_DIR"]))
    try:
        from runtime_paths import bundle_root
        folders.append(bundle_root() / "verifier")
    except Exception:
        pass
    for folder in folders:
        if folder.is_dir():
            found = sorted(p for p in folder.iterdir() if p.is_file() and p.name.startswith("veritas-verify"))
            if found:
                return found
    return []


def build(store, org: str, policy=None) -> tempfile.SpooledTemporaryFile:
    """The pack as a zip in a spooled file, positioned at the start. The caller closes it."""
    manager = anchor_cps.get_manager()
    files: Dict[str, bytes] = {}
    files["evidence.jsonl"] = "".join(anchor_export.evidence_lines(store, org)).encode("utf-8")
    files["checkpoints.jsonl"] = ("".join(anchor_export.checkpoint_lines(manager, org)) if manager else "").encode("utf-8")
    files["veritas.pub"] = anchor_export.public_key_text().encode("utf-8")
    s = gather(store, org, policy)
    files["summary.json"] = json.dumps(s, indent=2, sort_keys=True, default=str).encode("utf-8")
    files["SUMMARY.md"] = summary_markdown(s).encode("utf-8")
    files["VERIFY.md"] = verify_md().encode("utf-8")
    files["verify.sh"] = VERIFY_SH.encode("utf-8")
    files["verify.bat"] = VERIFY_BAT.encode("utf-8")
    binaries = {p.name: p.read_bytes() for p in _verifier_files()}
    manifest = "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in sorted({**files, **binaries}.items()))
    out = tempfile.SpooledTemporaryFile(max_size=MAX_BYTES_IN_MEMORY)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in {**files, **binaries}.items():
            info = zipfile.ZipInfo(name, date_time=datetime.now(timezone.utc).timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if name.startswith("verify.sh") or name.startswith("veritas-verify") else 0o644) << 16
            z.writestr(info, data)
        z.writestr("MANIFEST.sha256", manifest)
    out.seek(0)
    return out
