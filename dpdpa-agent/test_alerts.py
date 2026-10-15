"""Alerts reach a person, once, and never carry personal data."""
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import alerts


@pytest.fixture(autouse=True)
def clean(tmp_path, monkeypatch):
    for name in ("VERITAS_ALERT_WEBHOOK_URL", "VERITAS_ALERT_EMAIL_TO", "VERITAS_SMTP_HOST", "VERITAS_ALERT_MIN_SEVERITY",
                 "VERITAS_PUBLIC_URL", "VERITAS_SMTP_USER", "VERITAS_SMTP_PASSWORD", "VERITAS_SMTP_SECURITY", "VERITAS_SMTP_PORT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path))
    yield


class _Receiver:
    def __init__(self, status=200):
        outer = self
        self.bodies = []

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                outer.bodies.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(status); self.end_headers()

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}/hook"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


def test_nothing_configured_nothing_sent(monkeypatch):
    assert alerts.configured() == {"webhook": False, "email": False}
    assert alerts.send("s", "t") == {}
    sent = []
    monkeypatch.setattr(alerts._digest, "_sender", lambda *a: sent.append(a))
    alerts.notify_finding("org", "HIGH", "EXPOSURE_001", "aadhaar", 1, False)
    alerts._digest.flush()
    assert sent == []


def test_webhook_gets_json_with_text_and_structured_part(monkeypatch):
    r = _Receiver()
    try:
        monkeypatch.setenv("VERITAS_ALERT_WEBHOOK_URL", r.url)
        monkeypatch.setenv("VERITAS_PUBLIC_URL", "https://veritas.example:8000")
        out = alerts.send("[Veritas] subject", "body line", {"kind": "test"})
        assert out == {"webhook": "sent"}
        body = r.bodies[0]
        assert "[Veritas] subject" in body["text"] and "body line" in body["text"]
        assert "https://veritas.example:8000" in body["text"]
        assert body["veritas"] == {"kind": "test"}
    finally:
        r.close()


def test_a_failing_webhook_is_reported_not_raised(monkeypatch):
    r = _Receiver(status=500)
    try:
        monkeypatch.setenv("VERITAS_ALERT_WEBHOOK_URL", r.url)
        out = alerts.send("s", "t")
        assert out["webhook"].startswith("failed")
    finally:
        r.close()
    monkeypatch.setenv("VERITAS_ALERT_WEBHOOK_URL", "ftp://nope")
    assert alerts.send("s", "t")["webhook"].startswith("failed")


def test_email_goes_through_smtp_with_starttls_and_login(monkeypatch):
    log = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=0): log.append(("connect", host, port))
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self): log.append("starttls")
        def login(self, u, p): log.append(("login", u))
        def send_message(self, m): log.append(("send", m["To"], m["Subject"], m.get_content()))

    monkeypatch.setattr(alerts.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("VERITAS_ALERT_EMAIL_TO", "a@x.test, b@x.test")
    monkeypatch.setenv("VERITAS_SMTP_HOST", "mail.x.test")
    monkeypatch.setenv("VERITAS_SMTP_USER", "veritas")
    monkeypatch.setenv("VERITAS_SMTP_PASSWORD", "pw")
    assert alerts.send("Subject", "Body") == {"email": "sent"}
    assert ("connect", "mail.x.test", 587) in log and "starttls" in log and ("login", "veritas") in log
    sent = [x for x in log if isinstance(x, tuple) and x[0] == "send"][0]
    assert sent[1] == "a@x.test, b@x.test" and sent[2] == "Subject"


def test_email_needs_both_a_recipient_and_a_server(monkeypatch):
    monkeypatch.setenv("VERITAS_ALERT_EMAIL_TO", "a@x.test")
    assert alerts.configured()["email"] is False
    monkeypatch.setenv("VERITAS_SMTP_HOST", "mail")
    assert alerts.configured()["email"] is True


def _collect(monkeypatch):
    sent = []
    monkeypatch.setenv("VERITAS_ALERT_WEBHOOK_URL", "http://127.0.0.1:9/x")
    d = alerts._Digest(delay=3600, sender=lambda subject, text, data=None: sent.append((subject, text, data)))
    monkeypatch.setattr(alerts, "_digest", d)
    return sent, d


def test_only_serious_findings_are_sent_by_default(monkeypatch):
    sent, d = _collect(monkeypatch)
    alerts.notify_finding("org", "LOW", "RETENTION_001", "name", 1, False)
    alerts.notify_finding("org", "MEDIUM", "PURPOSE_001", "name", 2, False)
    alerts.notify_finding("org", "HIGH", "EXPOSURE_001", "aadhaar", 3, False)
    d.flush()
    assert len(sent) == 1 and "1 new finding in org" in sent[0][0]


def test_a_breach_candidate_is_always_sent_and_the_threshold_can_be_lowered(monkeypatch):
    sent, d = _collect(monkeypatch)
    alerts.notify_finding("org", "LOW", "X", "f", 1, True)
    d.flush()
    assert len(sent) == 1 and "breach notification" in sent[0][1]
    monkeypatch.setenv("VERITAS_ALERT_MIN_SEVERITY", "LOW")
    alerts.notify_finding("org", "LOW", "X", "f", 2, False)
    d.flush()
    assert len(sent) == 2


def test_a_burst_becomes_one_message_per_organization(monkeypatch):
    sent, d = _collect(monkeypatch)
    for i in range(50):
        alerts.notify_finding("org_a", "HIGH", "EXPOSURE_001", "aadhaar", i, False)
    alerts.notify_finding("org_b", "HIGH", "EXPOSURE_001", "pan", 1, False)
    d.flush()
    assert len(sent) == 2
    a = [s for s in sent if "org_a" in s[0]][0]
    assert "50 new findings" in a[0] and a[2]["count"] == 50
    assert len(a[1].splitlines()) <= 5          # not 50 lines


def test_messages_carry_names_and_counts_never_values(monkeypatch):
    sent, d = _collect(monkeypatch)
    alerts.notify_finding("org", "HIGH", "EXPOSURE_001", "aadhaar", 7, False, source_system="kyc-service")
    d.flush()
    text = sent[0][0] + sent[0][1]
    assert "aadhaar" in text and "#7" in text and "EXPOSURE_001" in text


def test_a_condition_is_sent_once_repeated_after_a_day_and_again_after_it_clears(monkeypatch):
    sent = []
    monkeypatch.setenv("VERITAS_ALERT_WEBHOOK_URL", "http://x")
    send = lambda subject, text, data=None: sent.append(subject)
    t0 = datetime(2026, 10, 15, 8, 0, tzinfo=timezone.utc)
    assert alerts.evaluate_conditions({"disk_low": "low"}, t0, send) == ["disk_low"]
    assert alerts.evaluate_conditions({"disk_low": "low"}, t0 + timedelta(hours=3), send) == []
    assert alerts.evaluate_conditions({"disk_low": "low"}, t0 + timedelta(hours=25), send) == ["disk_low"]
    assert alerts.evaluate_conditions({}, t0 + timedelta(hours=26), send) == []           # fixed
    assert alerts.evaluate_conditions({"disk_low": "low"}, t0 + timedelta(hours=27), send) == ["disk_low"]  # back
    assert len(sent) == 3


def test_without_a_channel_conditions_are_remembered_but_nothing_is_sent():
    sent = []
    t0 = datetime(2026, 10, 15, tzinfo=timezone.utc)
    assert alerts.evaluate_conditions({"backup_failed": "x"}, t0, lambda *a, **k: sent.append(a)) == []
    assert sent == []


def test_current_problems_reports_an_expiring_license_and_a_low_disk(monkeypatch):
    import types, sys
    lic = types.SimpleNamespace(days_remaining=12, expiry="2026-10-27")
    fake_license = types.ModuleType("license")
    class LicenseError(Exception): ...
    fake_license.LicenseError = LicenseError
    fake_license.validate_license = lambda: lic
    monkeypatch.setitem(sys.modules, "license", fake_license)
    monkeypatch.setattr(alerts.shutil if hasattr(alerts, "shutil") else __import__("shutil"), "disk_usage",
                        lambda p: types.SimpleNamespace(total=100 * 10**9, free=4 * 10**9, used=96 * 10**9))
    problems = alerts.current_problems()
    assert "license_expiring" in problems and "12 day" in problems["license_expiring"]
    assert "disk_low" in problems and "4%" in problems["disk_low"]
