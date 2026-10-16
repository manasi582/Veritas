"""
Veritas DPDPA Compliance Platform — Runtime Entry Point
=========================================================
Starts the Veritas compliance server. Events arrive exclusively from
registered Veritas Agents via POST /v1/{org_id}/events.

No synthetic data generators. No demo mode. Production only.

Usage:
    python run_pipeline.py              # start on port 8000 (HTTPS if cert available)
    python run_pipeline.py --port 8080  # custom port
    VERITAS_TLS=false python run_pipeline.py  # HTTP only (development)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time
from pathlib import Path

# Load .env (OPENAI_API_KEY, VERITAS_TLS etc.) — no-op if file doesn't exist
try:
    from dotenv import load_dotenv
    _env = Path(__file__).parent / ".env"
    if _env.exists():
        load_dotenv(_env)
except ImportError:
    _env = Path(__file__).parent / ".env"
    if _env.exists():
        with open(_env, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    os.environ.setdefault(_k.strip(), _v.strip())

import uvicorn

import settings_file

settings_file.load_into_environment()    # /etc/veritas/config.env: survives upgrades; the service definition still wins

from log_setup import configure_logging

import multiprocessing as _mp

if _mp.current_process().name == "MainProcess":
    configure_logging()
else:
    # a detection worker (see detection/pool.py): the main process owns the rotating log file
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("pipeline")

# Exit status used when the license is missing/invalid (see veritas.service).
LICENSE_EXIT_CODE = 78


def _load_settings(path: Path) -> None:
    """Put VERITAS_* settings from a config.env (Linux) or the service's .plist (macOS) into the environment."""
    values = {}
    try:
        if path.suffix == ".plist":
            import plistlib
            with open(path, "rb") as f:
                values = plistlib.load(f).get("EnvironmentVariables", {}) or {}
        else:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    values[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        return
    for k, v in values.items():
        if str(k).startswith("VERITAS_"):
            os.environ.setdefault(k, str(v))


def main() -> None:
    # Output to a pipe or file (the service log) is block-buffered by default, so the start-up
    # banner, which carries the setup code, could stay invisible for a long time. Flush per line.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    parser = argparse.ArgumentParser(
        description="Veritas DPDPA Compliance Platform"
    )
    parser.add_argument(
        "--port", type=int, default=8000,
        help="Dashboard port (default: 8000)",
    )
    parser.add_argument(
        "--fingerprint", action="store_true",
        help="Print this machine's license fingerprint and exit "
             "(send it to Veritas to receive a machine-bound license).",
    )
    parser.add_argument(
        "--setup-code", action="store_true",
        help="Print the one-time setup code needed to create the first administrator and exit.",
    )
    parser.add_argument(
        "--reset-password", metavar="USERNAME",
        help="Set a temporary password for a user and exit (for a lost administrator password). "
             "Run on the server; the user must choose a new password at next sign-in.",
    )
    parser.add_argument(
        "--install-cert", nargs=2, metavar=("CERT.pem", "KEY.pem"),
        help="Install a company-issued TLS certificate and its private key and exit "
             "(restart the service afterwards).",
    )
    parser.add_argument("--load-settings", metavar="FILE", help="Read VERITAS_* settings from a config.env or service .plist (for the command line tools).")
    parser.add_argument("--test-alert", action="store_true", help="Send a test message through the configured alert channels and exit.")
    parser.add_argument("--support-bundle", metavar="FILE", help="Write a support bundle (diagnostics, no secrets or customer data) and exit.")
    parser.add_argument("--support-log", metavar="FILE", action="append", default=[], help="With --support-bundle: a log file to include (its recent lines, redacted).")
    parser.add_argument("--backup-now", action="store_true", help="Create a backup now and exit.")
    parser.add_argument("--list-backups", action="store_true", help="List the available backups and exit.")
    parser.add_argument("--verify-backup", metavar="FILE", help="Check a backup file's integrity and exit.")
    parser.add_argument("--restore", metavar="FILE", help="Restore data from a backup file and exit (stop the service first).")
    parser.add_argument("--dry-run", action="store_true", help="With --restore: check the backup and show what would be restored.")
    parser.add_argument("--restore-license", action="store_true", help="With --restore: also replace the current license.")
    parser.add_argument("--force", action="store_true", help="With --restore: skip the running-server and newer-backup checks.")
    parser.add_argument(
        "--check", action="store_true",
        help="Run the production acceptance checks, print the report and exit.",
    )
    args = parser.parse_args()

    # ---- One-shot commands (no server start, no license required) ----
    if args.fingerprint:
        from license import FingerprintError, current_fingerprint
        try:
            print(current_fingerprint())
        except FingerprintError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            raise SystemExit(1)
        return

    if args.setup_code:
        from setup_code import from_environment, read_existing
        from user_store.store import get_user_store
        if get_user_store().count_users() > 0:
            print("Setup is already complete, so there is no setup code.", file=sys.stderr)
            raise SystemExit(1)
        code = read_existing()
        if not code:
            print("No setup code exists yet. Start the Veritas service first; it creates the code "
                  "when it starts.", file=sys.stderr)
            raise SystemExit(1)
        print(code)
        return

    if args.reset_password:
        from api.auth import _hash_password
        from api.passwords import generate_temporary_password
        from user_store.store import get_user_store
        store = get_user_store()
        target = store.get_by_username(args.reset_password.strip())
        if not target:
            print(f"ERROR: there is no user named {args.reset_password!r}.", file=sys.stderr)
            raise SystemExit(1)
        temp = generate_temporary_password()
        store.set_password(target.user_id, _hash_password(temp), must_change=True)
        try:
            from audit_log.store import get_audit_store
            get_audit_store().log("PASSWORD_RESET", actor_name="system (command line)",
                                  resource=f"user:{target.user_id}", detail={"username": target.username})
        except Exception:
            pass
        print(f"Temporary password for {target.username}: {temp}")
        print("It works once: the user must choose a new password at the next sign-in, and all of "
              "their current sessions have ended.")
        if not target.is_active:
            print(f"NOTE: the account is disabled. Another administrator can enable it on the Users page.",
                  file=sys.stderr)
        print("If the account was locked after failed sign-ins, the lock ends by itself within 15 minutes.")
        return

    if args.install_cert:
        from tls import CertificateError, install_certificate
        try:
            info = install_certificate(Path(args.install_cert[0]), Path(args.install_cert[1]))
        except CertificateError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            raise SystemExit(1)
        print("Certificate installed.")
        print(f"  Subject:  {info['subject']}")
        print(f"  Names:    {', '.join(info['names']) or '(none listed)'}")
        print(f"  Expires:  {info['not_after']} ({info['days_remaining']} days)")
        for w in info.get("warnings", []):
            print(f"  WARNING: {w}")
        if info["backup"]:
            print(f"  The previous certificate was kept as {info['backup']}")
        print("Restart Veritas to use it. Agents must trust the issuer (or be given the CA file).")
        return

    if args.backup_now or args.list_backups or args.verify_backup or args.restore:
        import backup
        if args.backup_now:
            try:
                print(f"Backup created: {backup.create_backup()}")
            except Exception as e:
                print(f"ERROR: {e}", file=sys.stderr)
                raise SystemExit(1)
        elif args.list_backups:
            found = backup.list_backups()
            if not found:
                print("No backups found.")
            for b in found:
                print(f"  {b['filename']}  {b['created_at'] or 'unknown'}  {(b['size_bytes'] or 0) / 1_048_576:.1f} MB")
        elif args.verify_backup:
            ok, errors = backup.verify_backup(Path(args.verify_backup))
            for e in errors:
                print(f"  ERROR: {e}", file=sys.stderr)
            print(("VERIFIED OK: " if ok else "VERIFICATION FAILED: ") + args.verify_backup)
            raise SystemExit(0 if ok else 1)
        else:
            result = backup.restore_backup(Path(args.restore), dry_run=args.dry_run,
                                           restore_license=args.restore_license, force=args.force)
            for f in result["restored_files"]:
                print(f"  {'would restore' if args.dry_run else 'restored'}: {f}")
            for f in result["skipped_files"]:
                print(f"  skipped: {f}")
            for w in dict.fromkeys(result["warnings"]):
                print(f"  NOTE: {w}")
            for e in result["errors"]:
                print(f"  ERROR: {e}", file=sys.stderr)
            if result["success"] and not args.dry_run:
                print(f"Restored {len(result['restored_files'])} files.")
                if result["safety_copy"]:
                    print(f"The data it replaced was kept in {result['safety_copy']} (delete it when you are satisfied).")
            elif result["success"]:
                print("DRY RUN OK: nothing was changed.")
            else:
                print("RESTORE FAILED. Your current data was left as it was (or put back).", file=sys.stderr)
            raise SystemExit(0 if result["success"] else 1)
        return

    if args.load_settings:
        _load_settings(Path(args.load_settings))

    if args.test_alert:
        import alerts
        if not alerts.any_configured():
            print("No alert channel is configured. Set VERITAS_ALERT_WEBHOOK_URL, or VERITAS_ALERT_EMAIL_TO with "
                  "VERITAS_SMTP_HOST (see OPERATIONS.md).", file=sys.stderr)
            raise SystemExit(1)
        results = alerts.send("[Veritas] Test alert", "This is a test message from Veritas. If you can read it, "
                              "alerts reach you.", {"kind": "test"})
        for channel, outcome in results.items():
            print(f"  {channel}: {outcome}")
        raise SystemExit(0 if all(v == "sent" for v in results.values()) else 1)

    if args.support_bundle:
        from support_bundle import build_bundle
        try:
            print(build_bundle(Path(args.support_bundle), log_files=[Path(p) for p in args.support_log]))
        except OSError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            raise SystemExit(1)
        raise SystemExit(0)

    if args.check:
        from production_check import print_report, run_checks
        report = run_checks()
        print_report(report)
        raise SystemExit(0 if (report["all_passed"] or report["has_warnings"]) else 1)

    # ---- License check ----
    from license import LicenseError, validate_license
    try:
        _lic = validate_license()
        print(
            f"[Veritas] License valid — {_lic.org} · {_lic.tier} · "
            f"expires {_lic.expiry} ({_lic.days_remaining}d remaining)"
        )
    except LicenseError as e:
        border = "=" * 60
        print(f"\n{border}\nLICENSE ERROR\n{border}\n{e}\n{border}\n")
        # 78 (EX_CONFIG): the systemd unit lists it in RestartPreventExitStatus,
        # so a missing/invalid license is reported once instead of crash-looping.
        raise SystemExit(LICENSE_EXIT_CODE)

    # ---- Data written by a newer release: stop with a clear reason instead of damaging it ----
    from schema_guard import SchemaTooNew, check_and_stamp
    try:
        check_and_stamp(__import__("runtime_paths").data_root())
    except SchemaTooNew as e:
        border = "=" * 60
        print(f"\n{border}\nDATA FORMAT ERROR\n{border}\n{e}\n{border}\n")
        raise SystemExit(LICENSE_EXIT_CODE)   # not fixable by restarting: report once, do not loop

    # ---- First-run: copy seed org configs out of the PyInstaller bundle ----
    from runtime_paths import bundle_root, data_root, is_bundled
    if is_bundled():
        import shutil as _shutil
        _src = bundle_root() / "org_config" / "configs"
        _dst = data_root()   / "org_config" / "configs"
        if _src.exists() and not _dst.exists():
            print("[Veritas] First run — copying org configs to data directory...")
            _shutil.copytree(str(_src), str(_dst))

    # ---- Production acceptance check (Phase 32) ----
    try:
        from production_check import print_report, run_checks
        _prod_report = run_checks()
        if not _prod_report["all_passed"]:
            print_report(_prod_report)
            _failed = [r for r in _prod_report["results"] if r["status"] == "fail"]
            if _failed:
                # License failure is already caught above and is fatal.
                # Other failures are logged as warnings — server still starts.
                for r in _failed:
                    if r["check"] != "license":
                        logger.warning("Production check FAILED: %s — %s", r["check"], r["message"])
    except Exception as _e:
        logger.debug("Production check skipped: %s", _e)

    # ---- PII log filter (Phase 9) ----
    try:
        from pii_guard import install_pii_log_filter
        install_pii_log_filter()
    except Exception:
        pass

    # ---- Secrets hardening (Phase 16) ----
    try:
        from secret_manager import harden_all_secrets
        harden_all_secrets()
    except Exception:
        pass

    # ---- Database encryption key init (Phase 17) ----
    try:
        from db_encryption import _load_or_generate_key
        _load_or_generate_key()
    except Exception:
        pass

    # ---- TLS configuration ----
    from tls import cert_fingerprint, get_ssl_params, tls_mode
    ssl_params = get_ssl_params()
    scheme = "https" if ssl_params else "http"

    # When TLS is active, auto-enable secure cookies unless explicitly overridden
    if ssl_params and "VERITAS_SECURE_COOKIES" not in os.environ:
        os.environ["VERITAS_SECURE_COOKIES"] = "true"
    elif not ssl_params and "VERITAS_SECURE_COOKIES" not in os.environ:
        os.environ["VERITAS_SECURE_COOKIES"] = "false"

    # ---- Start the FastAPI server (dashboard + API + WebSocket) ----
    def _run_server() -> None:
        from dashboard.server import app
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=args.port,
            log_level="warning",
            **(ssl_params or {}),
        )

    server_thread = threading.Thread(target=_run_server, daemon=True)
    server_thread.start()

    dashboard_url = f"{scheme}://localhost:{args.port}"
    logger.info("Dashboard: %s", dashboard_url)

    if ssl_params:
        fp = cert_fingerprint()
        if fp:
            logger.info("TLS certificate fingerprint (SHA-256): %s", fp)
            logger.info(
                "Share the certificate at %s with Veritas Agents "
                "(set VERITAS_CA_CERT on each agent).",
                data_root() / "certs" / "server.crt",
            )
    else:
        logger.warning(
            "Running over HTTP (TLS mode: %s). "
            "Not suitable for production — agent data is unencrypted in transit.",
            tls_mode(),
        )

    # First-boot check: if no users exist, print setup instructions
    try:
        from user_store.store import get_user_store
        if get_user_store().count_users() == 0:
            from setup_code import from_environment, get_or_create
            preset = from_environment() is not None
            code = get_or_create()
            print()
            print("=" * 60)
            print("  FIRST RUN DETECTED — SETUP REQUIRED")
            print("=" * 60)
            print(f"  Open {dashboard_url}/setup to create")
            print("  your administrator account before logging in.")
            print()
            if preset:
                print("  SETUP CODE: the value of the VERITAS_SETUP_CODE setting")
            else:
                print(f"  SETUP CODE: {code}")
                print("  (also shown by:  sudo veritas setup-code)")
            print("  The page asks for this code so that only someone with access")
            print("  to this server can create the first administrator.")
            print("=" * 60)
            print()
    except Exception:
        pass

    logger.info("Waiting for agents to connect and forward events...")

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Shutting down.")


if __name__ == "__main__":
    _mp.freeze_support()        # lets the packaged program start its detection workers
    main()
