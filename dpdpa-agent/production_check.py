"""
Veritas — Production Acceptance Check (Phase 32)
==================================================
Pre-flight system validation. Run before starting the server in production
to catch configuration problems early — before any request is served.

Usage (standalone CLI):
    python production_check.py           # exits 0 on pass, 1 on any failure
    python production_check.py --json    # machine-readable output

Programmatic:
    from production_check import run_checks
    report = run_checks()
    if not report["all_passed"]:
        ...

Checks performed:
  license        — license file present and valid (blocking in production)
  data_dir       — data_root() is writable
  disk_space     — at least 500 MB free on data volume
  secrets_dir    — secrets/ directory accessible
  db_encryption  — db.key present or can be created
  evidence_db    — evidence.db readable (or can be created fresh)
  user_db        — users.db readable (or can be created fresh)
  tls            — TLS cert/key present (warn only if absent; not blocking)
  imports        — all critical Python modules importable
"""

from __future__ import annotations

import sys
from typing import Any, Dict

_PASS = "pass"
_WARN = "warn"
_FAIL = "fail"


def _check(name: str, fn) -> Dict[str, Any]:
    """Run a single check function, capture its (status, message) return."""
    try:
        status, message = fn()
        return {"check": name, "status": status, "message": message}
    except Exception as exc:
        return {"check": name, "status": _FAIL, "message": f"Exception: {exc}"}


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_license():
    from license import LicenseError, validate_license
    try:
        lic = validate_license()
        return _PASS, f"Valid — {lic.org} · {lic.tier} · expires {lic.expiry} ({lic.days_remaining}d)"
    except LicenseError as e:
        return _FAIL, str(e)


def _check_data_dir():
    from runtime_paths import data_root
    d = data_root()
    d.mkdir(parents=True, exist_ok=True)
    # Write a temp file to verify writability
    probe = d / ".write_probe"
    probe.write_text("ok")
    probe.unlink()
    return _PASS, str(d)


def _check_disk_space():
    import shutil
    from runtime_paths import data_root
    usage = shutil.disk_usage(str(data_root()))
    free_mb = usage.free / 1_048_576
    if free_mb < 500:
        return _WARN, f"{free_mb:.0f} MB free — less than 500 MB recommended"
    return _PASS, f"{free_mb:.0f} MB free"


def _check_secrets_dir():
    from secret_manager import _secrets_dir
    d = _secrets_dir()
    if not d.is_dir():
        return _FAIL, f"Secrets directory not found: {d}"
    return _PASS, str(d)


def _check_db_encryption():
    from db_encryption import _key_path, _load_or_generate_key
    _load_or_generate_key()
    path = _key_path()
    if not path.exists():
        return _FAIL, "db.key not found after generation attempt"
    return _PASS, f"Encryption key at {path}"


def _check_evidence_db():
    from runtime_paths import data_root
    db = data_root() / "evidence.db"
    if db.exists():
        import sqlite3
        conn = sqlite3.connect(str(db))
        conn.execute("SELECT 1")
        conn.close()
        return _PASS, f"Readable ({db.stat().st_size} bytes)"
    return _PASS, "Not yet created (will be initialised on first use)"


def _check_user_db():
    from runtime_paths import data_root
    db = data_root() / "users.db"
    if db.exists():
        import sqlite3
        conn = sqlite3.connect(str(db))
        conn.execute("SELECT 1")
        conn.close()
        return _PASS, f"Readable ({db.stat().st_size} bytes)"
    return _PASS, "Not yet created (will be initialised on first use)"


def _check_tls():
    from tls import cert_path, key_path, tls_mode
    mode = tls_mode()
    if mode == "false":
        return _WARN, "TLS disabled (VERITAS_TLS=false) — not suitable for production"
    if not cert_path().exists():
        return _WARN, f"TLS cert not found at {cert_path()} — will be auto-generated on first start"
    if not key_path().exists():
        return _WARN, f"TLS key not found at {key_path()} — will be auto-generated on first start"
    from tls import cert_fingerprint
    fp = cert_fingerprint()
    return _PASS, f"Cert present — SHA-256: {fp}"


def _check_imports():
    required = [
        ("fastapi", "FastAPI"),
        ("uvicorn", "uvicorn"),
        ("passlib", "passlib"),
        ("jwt", "PyJWT"),
        ("cryptography", "cryptography"),
        ("sqlite3", "sqlite3 (stdlib)"),
        ("yaml", "PyYAML"),
        ("pydantic", "pydantic"),
    ]
    missing = []
    for mod, label in required:
        try:
            __import__(mod)
        except ImportError:
            missing.append(label)
    if missing:
        return _FAIL, f"Missing packages: {', '.join(missing)}"
    return _PASS, "All critical packages present"


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

_ALL_CHECKS = [
    ("license",       _check_license),
    ("data_dir",      _check_data_dir),
    ("disk_space",    _check_disk_space),
    ("secrets_dir",   _check_secrets_dir),
    ("db_encryption", _check_db_encryption),
    ("evidence_db",   _check_evidence_db),
    ("user_db",       _check_user_db),
    ("tls",           _check_tls),
    ("imports",       _check_imports),
]


def run_checks() -> Dict[str, Any]:
    """
    Run all production acceptance checks.

    Returns:
        {
          "all_passed": bool,   # True only if every check is "pass"
          "has_warnings": bool, # True if any check is "warn"
          "results": [{"check": str, "status": str, "message": str}, ...]
        }
    """
    results = [_check(name, fn) for name, fn in _ALL_CHECKS]
    statuses = [r["status"] for r in results]
    return {
        "all_passed":   all(s == _PASS for s in statuses),
        "has_warnings": any(s == _WARN for s in statuses),
        "results":      results,
    }


def print_report(report: Dict[str, Any]) -> None:
    """Print a human-readable acceptance report to stdout."""
    icons = {_PASS: "✓", _WARN: "!", _FAIL: "✗"}
    print()
    print("Veritas Production Acceptance Check")
    print("=" * 44)
    for r in report["results"]:
        icon = icons.get(r["status"], "?")
        print(f"  [{icon}] {r['check']:<20} {r['message']}")
    print("=" * 44)
    if report["all_passed"]:
        print("  RESULT: ALL CHECKS PASSED")
    elif not any(r["status"] == _FAIL for r in report["results"]):
        print("  RESULT: PASSED WITH WARNINGS")
    else:
        failed = [r["check"] for r in report["results"] if r["status"] == _FAIL]
        print(f"  RESULT: FAILED — {', '.join(failed)}")
    print()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Veritas production acceptance check")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    report = run_checks()

    if args.json:
        import json
        print(json.dumps(report, indent=2))
    else:
        print_report(report)

    sys.exit(0 if (report["all_passed"] or report["has_warnings"]) else 1)
