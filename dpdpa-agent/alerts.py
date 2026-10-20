"""
Alerts: tell a person when something needs them, without anyone watching the dashboard.

Two channels, both optional, set in the service's environment:

  VERITAS_ALERT_WEBHOOK_URL   an incoming-webhook URL (Slack, Microsoft Teams, Mattermost, or your own
                              receiver). Veritas POSTs {"text": "...", "veritas": {...}} as JSON.
  VERITAS_ALERT_EMAIL_TO      one or more addresses, comma separated, with
  VERITAS_SMTP_HOST           the mail server, and optionally
  VERITAS_SMTP_PORT           (default 587)
  VERITAS_SMTP_USER / VERITAS_SMTP_PASSWORD
  VERITAS_SMTP_FROM           (default veritas@<this host>)
  VERITAS_SMTP_SECURITY       starttls (default) | ssl | none

What is sent:
  * new findings of severity HIGH (or any breach-notification candidate), gathered into one message a
    minute so a burst does not become a flood (VERITAS_ALERT_MIN_SEVERITY=MEDIUM or LOW to widen it);
  * conditions that need action: a failed backup, a broken evidence chain, a license or TLS certificate
    that expires within 30 days, a disk that is nearly full. Each is sent once, again after 24 hours
    while it lasts, and once more if it comes back after being fixed.

A message never carries a personal data value, an explanation text or a secret: only counts, rule
names, field names, the organization and the severity. VERITAS_PUBLIC_URL (for example
https://veritas.example.com:8000) adds a link to the dashboard.
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
import socket
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("veritas.alerts")

CONDITION_REPEAT_HOURS = 24
DIGEST_SECONDS = 60
LICENSE_WARN_DAYS = 30
CERT_WARN_DAYS = 30
DISK_WARN_PERCENT = 10.0
_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


# --------------------------------------------------------------------------- configuration

def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def configured() -> Dict[str, bool]:
    return {
        "webhook": bool(_env("VERITAS_ALERT_WEBHOOK_URL")),
        "email": bool(_env("VERITAS_ALERT_EMAIL_TO") and _env("VERITAS_SMTP_HOST")),
    }


def any_configured() -> bool:
    return any(configured().values())


def _min_severity() -> int:
    return _SEVERITY_ORDER.get(_env("VERITAS_ALERT_MIN_SEVERITY").upper() or "HIGH", 2)


def _dashboard_link() -> str:
    url = _env("VERITAS_PUBLIC_URL")
    return f"\nOpen: {url}" if url else ""


# --------------------------------------------------------------------------- transports

def _post_webhook(url: str, text: str, data: dict) -> None:
    if not url.lower().startswith(("https://", "http://")):
        raise ValueError("the webhook address must start with https:// or http://")
    body = json.dumps({"text": text, "veritas": data}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json",
                                                          "User-Agent": "Veritas-Alerts"})
    with urllib.request.urlopen(req, timeout=10) as resp:      # noqa: S310 - the administrator chose the URL
        if resp.status >= 300:
            raise RuntimeError(f"the webhook answered {resp.status}")


def _send_email(subject: str, text: str) -> None:
    recipients = [a.strip() for a in _env("VERITAS_ALERT_EMAIL_TO").split(",") if a.strip()]
    host = _env("VERITAS_SMTP_HOST")
    port = int(_env("VERITAS_SMTP_PORT") or 587)
    security = (_env("VERITAS_SMTP_SECURITY") or "starttls").lower()
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = _env("VERITAS_SMTP_FROM") or f"veritas@{socket.getfqdn()}"
    msg["To"] = ", ".join(recipients)
    msg.set_content(text)
    smtp = smtplib.SMTP_SSL(host, port, timeout=15) if security == "ssl" else smtplib.SMTP(host, port, timeout=15)
    with smtp:
        if security == "starttls":
            smtp.starttls()
        if _env("VERITAS_SMTP_USER"):
            smtp.login(_env("VERITAS_SMTP_USER"), _env("VERITAS_SMTP_PASSWORD"))
        smtp.send_message(msg)


def send(subject: str, text: str, data: Optional[dict] = None) -> Dict[str, str]:
    """Send to every configured channel. Never raises; returns {channel: "sent" | error text}."""
    data = data or {}
    full = text + _dashboard_link()
    result: Dict[str, str] = {}
    cfg = configured()
    if cfg["webhook"]:
        try:
            _post_webhook(_env("VERITAS_ALERT_WEBHOOK_URL"), f"{subject}\n{full}", data)
            result["webhook"] = "sent"
        except Exception as e:                      # a broken channel must not break the server
            result["webhook"] = f"failed: {e}"
            logger.warning("Alert webhook failed: %s", e)
    if cfg["email"]:
        try:
            _send_email(subject, full)
            result["email"] = "sent"
        except Exception as e:
            result["email"] = f"failed: {e}"
            logger.warning("Alert e-mail failed: %s", e)
    return result


# --------------------------------------------------------------------------- findings (digest)

class _Digest:
    def __init__(self, delay: float = DIGEST_SECONDS, sender: Callable = send):
        self._lock = threading.Lock()
        self._items: List[dict] = []
        self._timer: Optional[threading.Timer] = None
        self.delay = delay
        self._sender = sender

    def add(self, item: dict) -> None:
        with self._lock:
            self._items.append(item)
            if self._timer is None:
                self._timer = threading.Timer(self.delay, self.flush)
                self._timer.daemon = True
                self._timer.start()

    def flush(self) -> None:
        with self._lock:
            items, self._items, self._timer = self._items, [], None
        if not items:
            return
        by_org: Dict[str, List[dict]] = {}
        for it in items:
            by_org.setdefault(it["org"], []).append(it)
        for org, rows in by_org.items():
            n = len(rows)
            breaches = sum(1 for r in rows if r["breach"])
            rules = Counter(r["rule"] for r in rows)
            fields = sorted({r["field"] for r in rows if r["field"]})[:8]
            numbers = [r["number"] for r in rows if r["number"]][:10]
            lines = [f"{n} new finding{'s' if n != 1 else ''} in {org}"
                     f" ({', '.join(f'{k} x{v}' for k, v in rules.most_common())})."]
            if breaches:
                lines.append(f"{breaches} may need breach notification (DPDPA section 8(6)).")
            if fields:
                lines.append("Fields: " + ", ".join(fields) + ".")
            if numbers:
                lines.append("Violation numbers: " + ", ".join(f"#{x}" for x in numbers) + ".")
            self._sender(f"[Veritas] {n} new finding{'s' if n != 1 else ''} in {org}", "\n".join(lines),
                         {"kind": "findings", "org": org, "count": n, "breach_candidates": breaches})


_digest = _Digest()


def notify_finding(org: str, severity: str, rule: str, field: str, violation_number: Optional[int],
                   breach: bool, source_system: str = "") -> None:
    """Called for every stored finding. Cheap when nothing is configured or the finding is minor."""
    if not any_configured():
        return
    if not breach and _SEVERITY_ORDER.get(str(severity).upper(), 0) < _min_severity():
        return
    _digest.add({"org": org, "severity": severity, "rule": rule, "field": field,
                 "number": violation_number, "breach": bool(breach), "source": source_system})


# --------------------------------------------------------------------------- conditions

def _state_path() -> Path:
    from runtime_paths import data_root
    return data_root() / "alerts_state.json"


def _read_state() -> Dict[str, str]:
    try:
        return json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_state(state: Dict[str, str]) -> None:
    path = _state_path()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def evaluate_conditions(problems: Dict[str, str], now: Optional[datetime] = None,
                        sender: Callable = send) -> List[str]:
    """
    `problems` maps a condition name to its message for everything that is wrong right now.
    Sends the new ones, repeats those unresolved for a day, forgets the resolved. Returns the names sent.
    """
    now = now or datetime.now(timezone.utc)
    state = _read_state()
    sent: List[str] = []
    for name in list(state):
        if name not in problems:
            del state[name]                       # fixed: if it comes back it is news again
    for name, message in problems.items():
        last = state.get(name)
        due = last is None
        if not due:
            try:
                due = now - datetime.fromisoformat(last) >= timedelta(hours=CONDITION_REPEAT_HOURS)
            except ValueError:
                due = True
        if due and any_configured():
            sender(f"[Veritas] Needs attention: {name.replace('_', ' ')}", message, {"kind": "condition", "name": name})
            state[name] = now.isoformat()
            sent.append(name)
        elif due:
            state.setdefault(name, now.isoformat())
    _write_state(state)
    return sent


def current_problems() -> Dict[str, str]:
    """Everything that needs action right now, from the same sources the dashboard's health card uses."""
    problems: Dict[str, str] = {}
    try:
        import maintenance
        m = maintenance.assess()
        if m.get("status") == "error":
            name = "evidence_chain_broken" if m.get("chains_broken") else "backup_failed"
            problems[name] = m.get("problem", "A backup or chain check failed.")
        elif m.get("status") == "stale":
            problems["backup_overdue"] = m.get("problem", "No recent backup.")
    except Exception as e:
        logger.debug("alert check: maintenance status unavailable: %s", e)
    try:
        from license import LicenseError, validate_license
        try:
            lic = validate_license()
            if lic.days_remaining <= LICENSE_WARN_DAYS:
                problems["license_expiring"] = (f"The Veritas license expires in {lic.days_remaining} day(s), on "
                                                f"{lic.expiry}. Ask your Veritas contact for a renewal and install "
                                                f"it with: veritas license <file>")
        except LicenseError as e:
            problems["license_invalid"] = str(e).splitlines()[0]
    except Exception as e:
        logger.debug("alert check: license status unavailable: %s", e)
    try:
        from tls import cert_days_remaining
        days = cert_days_remaining()
        if days is not None and days <= CERT_WARN_DAYS:
            problems["certificate_expiring"] = (f"The server's TLS certificate expires in {days} day(s). Install a "
                                                f"new one before then (veritas install-cert).")
    except Exception as e:
        logger.debug("alert check: certificate status unavailable: %s", e)
    try:
        import shutil
        from runtime_paths import data_root
        u = shutil.disk_usage(data_root())
        pct = 100.0 * u.free / u.total
        if pct < DISK_WARN_PERCENT:
            problems["disk_low"] = f"Only {pct:.0f}% of the disk is free ({u.free / 1e9:.1f} GB). Free space or move the data."
    except Exception as e:
        logger.debug("alert check: disk status unavailable: %s", e)
    try:    # retention: declared periods that have run out (or will soon) for data that is still being seen
        from config_loader import load_org_config
        from evidence_store.store import get_store
        from retention_review import review as _retention
        store = get_store()
        for org in store.tenants():
            try:
                cfg = load_org_config(org)
            except Exception:
                continue
            found = _retention.review(store, org, cfg)
            over = [i for i in found["items"] if i["status"] == _retention.OVERDUE]
            soon = [i for i in found["items"] if i["status"] == _retention.DUE_SOON]
            if over:
                problems[f"retention_overdue_{org}"] = (
                    f"{org}: {len(over)} declared retention period(s) have run out and data of that kind is still being seen: "
                    + ", ".join(sorted({f"{i['system']} ({i['field']})" for i in over})[:8])
                    + ". Open the Retention panel on the Data map and ask each owner to confirm.")
            if soon:
                problems[f"retention_due_soon_{org}"] = (
                    f"{org}: {len(soon)} declared retention period(s) run out within {found['settings']['warn_days']} days: "
                    + ", ".join(sorted({f"{i['system']} ({i['field']})" for i in soon})[:8]) + ".")
    except Exception as e:
        logger.debug("alert check: retention status unavailable: %s", e)
    return problems


def check_and_alert() -> List[str]:
    """One pass over the conditions. Called after every maintenance run and at start."""
    try:
        return evaluate_conditions(current_problems())
    except Exception:
        logger.exception("Alert check failed")
        return []
