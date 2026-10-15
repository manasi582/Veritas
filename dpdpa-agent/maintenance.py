"""
Routine upkeep that a compliance appliance must do by itself: a daily backup (kept for a
number of days) and a check that every organization's evidence hash chain is intact. The
result is stored in a small status file so the dashboard can show a warning when a backup is
overdue or the chain is broken, instead of that being found out during an audit.

Settings (environment):
  VERITAS_BACKUP_INTERVAL_HOURS  hours between runs, default 24; 0 turns the schedule off
  VERITAS_BACKUP_KEEP            how many backups to keep, default 7
  VERITAS_BACKUP_DIR             where backups go, default <data dir>/backups
                                 (point it at another disk or a network mount for safety)
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("veritas.maintenance")

DEFAULT_INTERVAL_HOURS = 24.0
DEFAULT_KEEP = 7
FIRST_RUN_DELAY_SECONDS = 600       # let the server settle after a start before the first backup


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        logger.warning("%s is not a number; using %s", name, default)
        return default


def interval_hours() -> float:
    return max(0.0, _env_float("VERITAS_BACKUP_INTERVAL_HOURS", DEFAULT_INTERVAL_HOURS))


def keep_count() -> int:
    return max(1, int(_env_float("VERITAS_BACKUP_KEEP", DEFAULT_KEEP)))


def backup_dir() -> Path:
    from runtime_paths import data_root
    env = os.environ.get("VERITAS_BACKUP_DIR", "").strip()
    return Path(env) if env else data_root() / "backups"


def status_path() -> Path:
    from runtime_paths import data_root
    return data_root() / "maintenance_status.json"


def read_status() -> dict:
    try:
        return json.loads(status_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_status(status: dict) -> None:
    path = status_path()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(status, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def check_chains(orgs: Optional[List[str]] = None) -> Dict[str, dict]:
    """Verify the evidence hash chain of each organization. {org: {"valid": bool, ...}}"""
    from evidence_store.store import get_store
    if orgs is None:
        from org_config.store import list_registered_orgs
        orgs = list_registered_orgs()
    store = get_store()
    results = {}
    for org in orgs:
        try:
            results[org] = store.verify_chain(org)
        except Exception as e:                      # one broken org must not hide the others
            logger.error("Chain check failed to run for %s: %s", org, e)
            results[org] = {"valid": False, "first_broken_index": None, "error": str(e)}
    return results


def prune_backups(directory: Path, keep: int) -> List[str]:
    """Delete all but the newest `keep` backups. Returns the names removed."""
    files = sorted(directory.glob("veritas-backup-*.zip"), key=lambda f: f.name, reverse=True)
    removed = []
    for old in files[keep:]:
        try:
            old.unlink()
            removed.append(old.name)
        except OSError as e:
            logger.warning("Could not delete old backup %s: %s", old.name, e)
    return removed


def _audit(action: str, result: str, detail: dict) -> None:
    try:
        from audit_log.store import get_audit_store
        get_audit_store().log(action, actor_name="system", result=result, detail=detail)
    except Exception:
        pass


def log_license_expiry() -> None:
    """Write a log line when the license is close to its end, so it shows up in monitoring."""
    try:
        from license import LicenseError, validate_license
        try:
            info = validate_license()
        except LicenseError as e:
            logger.error("LICENSE PROBLEM: %s", str(e).splitlines()[0])
            return
        if info.days_remaining <= 30:
            logger.warning("The Veritas license expires in %d day(s), on %s. Ask your Veritas contact for a "
                           "renewal and install it with: sudo veritas license <file>",
                           info.days_remaining, info.expiry)
    except Exception:
        pass


def run_once(now: Optional[datetime] = None) -> dict:
    """One maintenance pass: backup, prune, verify chains. Always records the outcome."""
    from backup import create_backup
    now = now or datetime.now(timezone.utc)
    status = read_status()
    log_license_expiry()

    # ---- backup ----
    try:
        directory = backup_dir()
        directory.mkdir(parents=True, exist_ok=True)
        path = create_backup(directory / f"veritas-backup-{now.strftime('%Y%m%dT%H%M%SZ')}.zip")
        removed = prune_backups(directory, keep_count())
        status.update(last_backup_at=now.isoformat(), last_backup_file=path.name,
                      last_backup_ok=True, last_backup_error=None, pruned=removed)
        logger.info("Scheduled backup done: %s (removed %d old)", path.name, len(removed))
        _audit("BACKUP_CREATED", "SUCCESS", {"file": path.name, "scheduled": True})
    except Exception as e:
        logger.error("Scheduled backup FAILED: %s", e)
        status.update(last_backup_attempt_at=now.isoformat(), last_backup_ok=False, last_backup_error=str(e)[:300])
        _audit("BACKUP_CREATED", "FAILURE", {"error": str(e)[:300], "scheduled": True})

    # ---- evidence chains ----
    try:
        chains = check_chains()
        broken = sorted(org for org, r in chains.items() if not r.get("valid"))
        status.update(last_chain_check_at=now.isoformat(), chains_checked=len(chains), chains_broken=broken)
        if broken:
            logger.error("EVIDENCE CHAIN BROKEN for: %s. The stored evidence no longer matches its hashes.",
                         ", ".join(broken))
        _audit("CHAIN_VERIFIED", "FAILURE" if broken else "SUCCESS",
               {"organizations": len(chains), "broken": broken, "scheduled": True})
    except Exception as e:
        logger.error("Scheduled chain check FAILED to run: %s", e)
        status.update(last_chain_check_at=now.isoformat(), chain_check_error=str(e)[:300])

    _write_status(status)
    try:
        import alerts
        alerts.check_and_alert()          # a failed backup or a broken chain reaches a person
    except Exception:
        logger.debug("alert check skipped", exc_info=True)
    return status


def assess(status: Optional[dict] = None, now: Optional[datetime] = None) -> dict:
    """
    What the dashboard shows: {"status": "ok"|"disabled"|"pending"|"stale"|"error", ...details}.
    "error" is a failed backup or a broken chain; "stale" is a backup older than twice the interval.
    """
    status = read_status() if status is None else status
    now = now or datetime.now(timezone.utc)
    hours = interval_hours()
    out = {k: status.get(k) for k in ("last_backup_at", "last_backup_file", "last_chain_check_at",
                                      "chains_checked", "chains_broken", "last_backup_error")}
    out["interval_hours"] = hours
    if status.get("chains_broken"):
        out["status"] = "error"
        out["problem"] = "Evidence chain broken for: " + ", ".join(status["chains_broken"])
    elif status.get("last_backup_ok") is False:
        out["status"] = "error"
        out["problem"] = "The last scheduled backup failed: " + str(status.get("last_backup_error") or "unknown error")
    elif hours == 0:
        out["status"] = "disabled"
    elif not status.get("last_backup_at"):
        out["status"] = "pending"           # nothing has run yet (the first run follows the start)
    else:
        last = datetime.fromisoformat(status["last_backup_at"])
        if now - last > timedelta(hours=hours * 2 + 1):
            out["status"] = "stale"
            out["problem"] = f"No successful backup since {last.date().isoformat()}."
        else:
            out["status"] = "ok"
    return out


def _loop(stop: threading.Event, first_delay: float, sleep: Callable[[float], bool]) -> None:
    hours = interval_hours()
    if hours <= 0:
        logger.info("Scheduled backups are turned off (VERITAS_BACKUP_INTERVAL_HOURS=0).")
        return
    # If the last run is recent, wait out the rest of the interval instead of backing up on every restart.
    status = read_status()
    delay = first_delay
    if status.get("last_backup_at"):
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(status["last_backup_at"])).total_seconds()
            delay = max(first_delay, hours * 3600 - age)
        except ValueError:
            pass
    logger.info("Scheduled backups every %.4g h, keeping %d; next run in %.0f min.", hours, keep_count(), delay / 60)
    if sleep(delay):
        return
    while not stop.is_set():
        try:
            run_once()
        except Exception:
            logger.exception("Maintenance pass crashed; will try again at the next interval")
        if sleep(hours * 3600):
            return


def start(first_delay: float = FIRST_RUN_DELAY_SECONDS) -> threading.Event:
    """Start the schedule in a background thread. Set the returned event to stop it."""
    stop = threading.Event()
    threading.Thread(target=_loop, args=(stop, first_delay, stop.wait), name="veritas-maintenance",
                     daemon=True).start()
    return stop
