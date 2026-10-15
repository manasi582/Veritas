"""
Metrics in the Prometheus text format, for the customer's own monitoring (Prometheus, Grafana,
Datadog agent, Zabbix with a Prometheus plugin...).

Off unless VERITAS_METRICS_TOKEN is set. `GET /metrics` then needs `Authorization: Bearer <that token>`.
The token is chosen by the administrator and is not a user session. Nothing here is personal data:
counts, ages, sizes and the release number.
"""
from __future__ import annotations

import hmac
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


def token() -> str:
    return os.environ.get("VERITAS_METRICS_TOKEN", "").strip()


def token_ok(authorization_header: Optional[str]) -> bool:
    """Constant-time check; always False when metrics are off or the token is shorter than 16 characters."""
    expected = token()
    if len(expected) < 16 or not authorization_header:
        return False
    scheme, _, supplied = authorization_header.partition(" ")
    return scheme.lower() == "bearer" and hmac.compare_digest(supplied.strip().encode(), expected.encode())


def _label(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ")


def _line(name: str, value: float, **labels: object) -> str:
    lab = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
    return f"{name}{{{lab}}} {value}" if lab else f"{name} {value}"


def render() -> str:
    """The metrics text. Each source that cannot be read is simply left out: a scrape never fails."""
    out: List[str] = []

    def metric(name: str, help_text: str, kind: str = "gauge") -> None:
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")

    from runtime_paths import data_root

    try:
        from veritas_version import get_version
        metric("veritas_info", "Always 1; the release is in the label.")
        out.append(_line("veritas_info", 1, version=get_version()))
    except Exception:
        pass

    try:
        from license import LicenseError, validate_license
        metric("veritas_license_valid", "1 when the license is valid for this machine.")
        try:
            lic = validate_license()
            out.append(_line("veritas_license_valid", 1))
            metric("veritas_license_days_remaining", "Days until the license expires.")
            out.append(_line("veritas_license_days_remaining", lic.days_remaining))
        except LicenseError:
            out.append(_line("veritas_license_valid", 0))
    except Exception:
        pass

    try:
        from tls import cert_days_remaining
        days = cert_days_remaining()
        if days is not None:
            metric("veritas_tls_certificate_days_remaining", "Days until the server's TLS certificate expires.")
            out.append(_line("veritas_tls_certificate_days_remaining", days))
    except Exception:
        pass

    try:
        u = shutil.disk_usage(data_root())
        metric("veritas_disk_free_percent", "Free space on the volume that holds Veritas's data.")
        out.append(_line("veritas_disk_free_percent", round(100.0 * u.free / u.total, 2)))
        metric("veritas_disk_free_bytes", "Free bytes on the volume that holds Veritas's data.")
        out.append(_line("veritas_disk_free_bytes", u.free))
    except Exception:
        pass

    try:
        metric("veritas_database_bytes", "Size of each database file.")
        for name in ("evidence.db", "agents.db", "users.db", "audit.db"):
            p = Path(data_root()) / name
            if p.is_file():
                out.append(_line("veritas_database_bytes", p.stat().st_size, database=name))
    except Exception:
        pass

    try:
        import maintenance
        m = maintenance.assess()
        metric("veritas_backup_last_ok", "1 when the last scheduled backup succeeded.")
        out.append(_line("veritas_backup_last_ok", 0 if m.get("status") == "error" and not m.get("chains_broken") else 1))
        if m.get("last_backup_at"):
            at = datetime.fromisoformat(m["last_backup_at"])
            metric("veritas_backup_age_seconds", "Seconds since the last successful backup.")
            out.append(_line("veritas_backup_age_seconds", int((datetime.now(timezone.utc) - at).total_seconds())))
        metric("veritas_evidence_chains_broken", "Organizations whose evidence chain failed verification.")
        out.append(_line("veritas_evidence_chains_broken", len(m.get("chains_broken") or [])))
    except Exception:
        pass

    try:
        from agent_store.store import get_agent_store
        from collections import Counter
        counts = Counter((a.org_id, a.status.value if hasattr(a.status, "value") else str(a.status))
                         for a in get_agent_store().list_agents())
        metric("veritas_agents", "Registered agents per organization and status.")
        for (org, status), n in sorted(counts.items()):
            out.append(_line("veritas_agents", n, org=org, status=status))
    except Exception:
        pass

    try:
        from evidence_store.store import get_store
        from org_config.store import list_registered_orgs
        store = get_store()
        metric("veritas_findings", "Findings per organization and remediation status.")
        for org in list_registered_orgs():
            for status, n in sorted(store.count_by_status(org).items()):
                out.append(_line("veritas_findings", n, org=org, status=status))
    except Exception:
        pass

    try:
        import alerts
        metric("veritas_alert_channel_configured", "1 for each alert channel that is set up.")
        for channel, on in alerts.configured().items():
            out.append(_line("veritas_alert_channel_configured", 1 if on else 0, channel=channel))
    except Exception:
        pass

    metric("veritas_scrape_timestamp_seconds", "When these numbers were taken.")
    out.append(_line("veritas_scrape_timestamp_seconds", int(time.time())))
    return "\n".join(out) + "\n"
