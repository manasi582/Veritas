"""The support bundle must be useful to the vendor and harmless if it is forwarded."""
import json
import zipfile

import pytest

import support_bundle as sb

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSIsInJvbGUiOiJTVVBFUl9BRE1JTiJ9.abcdefghijklmnopqrstuv"


@pytest.mark.parametrize("line", [
    f"cookie veritas_session={JWT}",
    f"Authorization: Bearer {JWT}",
    "Authorization: Bearer abc.def-123_456",
    'registration_key: "AkBOPDxxxxxxxxxxxxxxxx"',
    "registration_key=AkBOPDxxxxxxxxxxxxxxxx",
    '{"password": "Project@123", "user": "x"}',
    "setup_code: ABCD-EF12-GH34",
    "the setup code is ABCD-EF12-GH34 please",
    "agent token 9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928",
])
def test_secrets_are_removed(line):
    out = sb.redact(line)
    for secret in (JWT, "Project@123", "ABCD-EF12-GH34", "AkBOPDxxxxxxxxxxxxxxxx", "9f8e7d6c5b4a3928",
                   "abc.def-123_456"):
        assert secret not in out, (line, out)


def test_private_key_blocks_are_removed():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabcdef\n-----END RSA PRIVATE KEY-----"
    assert "MIIEow" not in sb.redact("before\n" + pem + "\nafter")


@pytest.mark.parametrize("line,gone", [
    ("customer Aadhaar 2345 6789 0123 leaked", "2345 6789 0123"),
    ("PAN ABCDE1234F in log", "ABCDE1234F"),
    ("phone +91 98765 43210 in log", "98765 43210"),
    ("phone 9876543210 in log", "9876543210"),
])
def test_personal_identifiers_are_removed(line, gone):
    assert gone not in sb.redact(line)


def test_things_a_diagnosis_needs_survive():
    line = "2026-10-15 17:56:33,001 INFO veritas.backup: RESTORE complete: 10 files restored, 1 skipped"
    assert sb.redact(line) == line
    fp = "v2:8a6df5669d103cfb9f4752ac0305f300e08c18baa0d2da030488ac685c4b932a"
    assert fp in sb.redact(f"fingerprint {fp}")
    assert "veritas-backup-20261014T174406Z.zip" in sb.redact("file veritas-backup-20261014T174406Z.zip")
    assert "https://localhost:8000/health" in sb.redact("GET https://localhost:8000/health")


def _make(tmp_path, monkeypatch, **kw):
    data = tmp_path / "data"
    (data / "secrets").mkdir(parents=True)
    (data / "secrets" / "db.key").write_text("TOPSECRETKEYMATERIALTOPSECRETKEYMATERIAL")
    (data / "secrets" / "jwt_secret.key").write_text("ANOTHERSECRETANOTHERSECRETANOTHERSECRET")
    (data / "evidence.db").write_bytes(b"SQLite format 3\x00" + b"PERSONAL-DATA-" * 50)
    (data / "veritas.vlic").write_text("-----BEGIN VERITAS LICENSE-----\nAAAA\n-----END VERITAS LICENSE-----")
    monkeypatch.setenv("VERITAS_DATA_DIR", str(data))
    monkeypatch.setenv("VERITAS_JWT_SECRET", "env-secret-value-env-secret-value-1234")
    monkeypatch.setenv("VERITAS_BACKUP_KEEP", "14")
    log = tmp_path / "veritas-app.log"
    log.write_text("\n".join(f"line {i} token=abcdef123456" for i in range(50)) + f"\nlast Bearer {JWT}\n")
    out = sb.build_bundle(tmp_path / "bundle.zip", data_dir=data, log_files=[log], lines=20, **kw)
    return zipfile.ZipFile(out), data


def test_bundle_holds_the_diagnostic_files(tmp_path, monkeypatch):
    z, _ = _make(tmp_path, monkeypatch)
    names = set(z.namelist())
    assert {"manifest.json", "license.json", "acceptance_check.json", "disk.json", "data_files.json",
            "settings.json", "logs/veritas-app.log"} <= names
    assert json.loads(z.read("manifest.json"))["veritas_version"]


def test_bundle_has_no_database_key_certificate_or_license_file(tmp_path, monkeypatch):
    z, _ = _make(tmp_path, monkeypatch)
    everything = b"".join(z.read(n) for n in z.namelist()).decode("utf-8", "replace")
    for forbidden in ("PERSONAL-DATA-", "TOPSECRETKEYMATERIAL", "ANOTHERSECRET", "SQLite format",
                      "BEGIN VERITAS LICENSE", "env-secret-value", JWT):
        assert forbidden not in everything, forbidden
    assert not any(n.endswith((".db", ".key", ".vlic", ".pem")) for n in z.namelist())


def test_data_files_are_listed_by_name_and_size_only(tmp_path, monkeypatch):
    z, _ = _make(tmp_path, monkeypatch)
    rows = json.loads(z.read("data_files.json"))
    by_name = {r["file"]: r for r in rows}
    assert by_name["evidence.db"]["bytes"] > 0 and set(by_name["evidence.db"]) == {"file", "bytes", "modified"}


def test_settings_show_values_except_secrets(tmp_path, monkeypatch):
    z, _ = _make(tmp_path, monkeypatch)
    settings = json.loads(z.read("settings.json"))
    assert settings["VERITAS_BACKUP_KEEP"] == "14"
    assert settings["VERITAS_JWT_SECRET"] == sb.REDACTED


def test_logs_are_cut_to_the_requested_tail_and_redacted(tmp_path, monkeypatch):
    z, _ = _make(tmp_path, monkeypatch)
    text = z.read("logs/veritas-app.log").decode()
    assert len(text.strip().splitlines()) == 20
    assert "abcdef123456" not in text and JWT not in text and "line 49" in text


def test_the_bundle_file_is_private(tmp_path, monkeypatch):
    import os
    import stat
    import sys
    z, _ = _make(tmp_path, monkeypatch)
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(tmp_path / "bundle.zip").st_mode) == 0o600


def test_a_missing_log_does_not_stop_the_bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path))
    out = sb.build_bundle(tmp_path / "b.zip", data_dir=tmp_path, log_files=[tmp_path / "nope.log"])
    assert "manifest.json" in zipfile.ZipFile(out).namelist()
