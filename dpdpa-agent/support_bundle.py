"""
Support bundle: one ZIP a customer can send to the vendor when something is wrong.

It holds what a person needs to diagnose a problem (version, license status, the acceptance check,
disk, which files exist and how big, the settings in effect, the recent log lines) and nothing that
is a secret or a customer's data: no database, no key, no certificate, no license file, no
password or token. Everything that is text goes through `redact()` first, because logs can hold
tokens and, despite the filter in the server, the odd personal identifier.

    sudo veritas support-bundle [file.zip]
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

REDACTED = "[REDACTED]"
DEFAULT_LOG_LINES = 1000

_SECRET_WORDS = r"(?:password|passwd|secret|token|api[_-]?key|registration[_-]?key|setup[_-]?code|authorization|cookie|private[_-]?key)"

# Order matters: the most specific first.
_RULES = [
    (re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"), REDACTED),                    # JWT
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]+"), "Bearer " + REDACTED),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), REDACTED),
    (re.compile(rf"(?i)(\"?{_SECRET_WORDS}\"?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"), r"\1" + REDACTED),     # key=value, key: "value", "key": "value"
    (re.compile(r"\b[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b"), REDACTED),                                     # setup code
    (re.compile(r"(?<!v2:)(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{32,}(?![A-Za-z0-9_\-])"), REDACTED),            # any long token (not a v2: fingerprint)
    (re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"), "[NUMBER-12]"),                                          # Aadhaar-shaped
    (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "[PAN]"),
    (re.compile(r"(?<!\d)(?:\+91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)"), "[PHONE]"),
]

# A setting whose name suggests a secret is shown as set or not, never with its value.
_SECRET_NAME = re.compile(_SECRET_WORDS, re.I)


def redact(text: str) -> str:
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


def _settings() -> Dict[str, str]:
    out = {}
    for name, value in sorted(os.environ.items()):
        if not name.startswith("VERITAS_"):
            continue
        out[name] = REDACTED if _SECRET_NAME.search(name) else redact(value)
    return out


def _license_summary() -> dict:
    try:
        from license import LicenseError, validate_license
        try:
            lic = validate_license()
            return {"valid": True, "org": lic.org, "tier": lic.tier, "expiry": str(lic.expiry),
                    "days_remaining": lic.days_remaining}
        except LicenseError as e:
            return {"valid": False, "problem": redact(str(e))}
    except Exception as e:  # pragma: no cover - the bundle must still be made
        return {"valid": None, "problem": f"could not check: {e}"}


def _checks() -> dict:
    try:
        from production_check import run_checks
        report = run_checks()
        for r in report.get("results", []):
            r["message"] = redact(str(r.get("message", "")))
        return report
    except Exception as e:  # pragma: no cover
        return {"error": str(e)}


def _disk(path: Path) -> dict:
    try:
        u = shutil.disk_usage(path)
        return {"path": str(path), "total_gb": round(u.total / 1e9, 1), "free_gb": round(u.free / 1e9, 1),
                "free_percent": round(100 * u.free / u.total, 1)}
    except OSError as e:
        return {"path": str(path), "error": str(e)}


def _listing(root: Path) -> List[dict]:
    """Names, sizes and ages of what is in the data folder. Never contents."""
    rows: List[dict] = []
    if not root.exists():
        return rows
    for p in sorted(root.rglob("*")):
        try:
            if p.is_dir():
                continue
            rel = p.relative_to(root)
            if len(rel.parts) > 3:
                continue
            st = p.stat()
            rows.append({"file": str(rel), "bytes": st.st_size,
                         "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(timespec="seconds")})
        except OSError:
            continue
    return rows


def _tail(path: Path, lines: int) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 2_000_000))
            chunk = f.read().decode("utf-8", "replace")
    except OSError as e:
        return f"[could not read {path.name}: {e}]\n"
    return "\n".join(chunk.splitlines()[-lines:]) + "\n"


def build_bundle(out_path: Path, *, data_dir: Optional[Path] = None, log_files: Iterable[Path] = (),
                 lines: int = DEFAULT_LOG_LINES) -> Path:
    from runtime_paths import data_root
    root = Path(data_dir) if data_dir else data_root()
    try:
        from veritas_version import get_version
        version = get_version()
    except Exception:  # pragma: no cover
        version = "unknown"

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "veritas_version": version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "what_is_in_this_file": "Version, license status, acceptance check, disk, file names and sizes, "
                                "settings (secrets hidden), recent log lines (tokens and personal identifiers "
                                "removed). No database, key, certificate, license file or password.",
    }
    sections = {
        "manifest.json": manifest,
        "license.json": _license_summary(),
        "acceptance_check.json": _checks(),
        "disk.json": _disk(root),
        "data_files.json": _listing(root),
        "settings.json": _settings(),
    }

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in sections.items():
            zf.writestr(name, json.dumps(content, indent=2, default=str))
        for log in log_files:
            log = Path(log)
            if log.is_file():
                zf.writestr(f"logs/{log.name}", redact(_tail(log, lines)))
    try:
        os.chmod(out_path, 0o600)
    except OSError:
        pass
    return out_path
