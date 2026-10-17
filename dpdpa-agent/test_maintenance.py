"""
Scheduled backups, evidence-chain checks, certificate installation and the alert data the
dashboard shows (health endpoint). Everything runs against a temporary data directory.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import backup
import os
import maintenance
import tls
from evidence_store.store import EvidenceStore
from llm_explainer.explainer import ExplainedVerdict
from schemas.models import RemediationStatus, RuleId, Severity, SourceType, Verdict


def _verdict(org: str) -> ExplainedVerdict:
    v = Verdict(
        tenant_id=org, verdict_id=uuid.uuid4(), event_id=uuid.uuid4(), rule_id=RuleId.EXPOSURE_001,
        severity=Severity.HIGH, source=SourceType.LOG, source_system="s", field="f",
        timestamp=datetime.now(timezone.utc), matched_registry_entry=None,
        breach_notification_candidate=False, remediation_status=RemediationStatus.OPEN,
        remediation_updated_at=None,
    )
    return ExplainedVerdict(verdict=v, explanation="x", section_cited="x", confidence=1.0, used_fallback=True)


@pytest.fixture
def data(tmp_path, monkeypatch):
    """A data directory with a real evidence database and two organizations registered."""
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path))
    for var in ("VERITAS_BACKUP_DIR", "VERITAS_BACKUP_INTERVAL_HOURS", "VERITAS_BACKUP_KEEP"):
        monkeypatch.delenv(var, raising=False)
    import evidence_store.store as ev
    monkeypatch.setattr(ev, "_DEFAULT_DB_PATH", tmp_path / "evidence.db")
    ev.reset_store()
    store = ev.get_store()
    for org in ("org_a", "org_b"):
        store.append(_verdict(org))
        store.append(_verdict(org))
    for name in ("agents.db", "users.db", "audit.db"):          # the other databases a backup holds
        c = sqlite3.connect(tmp_path / name); c.execute("CREATE TABLE t(x)"); c.commit(); c.close()
    import org_config.store as oc
    monkeypatch.setattr(oc, "list_registered_orgs", lambda: ["org_a", "org_b"])
    yield tmp_path
    ev.reset_store()


class TestBackup:
    def test_a_backup_of_a_live_database_restores_to_the_same_data(self, data, tmp_path_factory):
        path = backup.create_backup()
        assert path.exists()
        if sys.platform != "win32":      # Windows has no POSIX permission bits
            assert (path.stat().st_mode & 0o077) == 0, "backup must be owner-only"
        ok, errors = backup.verify_backup(path)
        assert ok, errors
        target = tmp_path_factory.mktemp("restore")
        result = backup.restore_backup(path, target_root=target)
        assert result["success"], result
        copy = EvidenceStore(db_path=target / "evidence.db")
        assert copy.verify_chain("org_a")["valid"] and copy.verify_chain("org_b")["valid"]
        assert copy.count("org_a") == 2
        copy.close()

    def test_backup_stays_consistent_while_the_server_is_writing(self, data):
        import evidence_store.store as ev
        store = ev.get_store()
        stop = threading.Event()

        def writer():
            while not stop.is_set():
                store.append(_verdict("org_a"))

        t = threading.Thread(target=writer); t.start()
        try:
            for i in range(5):
                path = backup.create_backup(data / "backups" / f"veritas-backup-live{i}.zip")
                copy_dir = data / f"r{i}"
                assert backup.restore_backup(path, target_root=copy_dir)["success"]
                copy = EvidenceStore(db_path=copy_dir / "evidence.db")
                assert copy.verify_chain("org_a")["valid"], "a torn copy of the database was backed up"
                copy.close()
        finally:
            stop.set(); t.join()


class TestRestore:
    """A restore must be safe: checked before it touches anything, undoable, and never a trap."""

    def _snapshot(self, root):
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*"))
                if p.is_file() and "backups" not in p.relative_to(root).parts}

    def _stop_service(self):
        """What stopping the real service does: no open handle on the databases (Windows cannot replace an open file)."""
        import evidence_store.store as ev
        ev.reset_store()

    def _live(self, data, monkeypatch):
        """Make `data` look like a live installation: files the restore replaces."""
        (data / "veritas.vlic").write_text("CURRENT LICENSE")
        (data / "secrets").mkdir(exist_ok=True); (data / "secrets" / "jwt_secret.key").write_text("old-secret")
        (data / "certs").mkdir(exist_ok=True); (data / "certs" / "server.crt").write_text("crt")
        monkeypatch.setattr(backup, "_server_running", lambda: False)

    def test_restore_replaces_live_data_and_keeps_a_safety_copy(self, data, monkeypatch):
        self._live(data, monkeypatch)
        path = backup.create_backup()
        import evidence_store.store as ev
        ev.get_store().append(_verdict("org_a"))          # data that exists only after the backup
        ev.reset_store()
        (data / "secrets" / "jwt_secret.key").write_text("changed-after-backup")
        (data / "certs" / "extra.pem").write_text("not in the backup")
        res = backup.restore_backup(path)
        assert res["success"], res
        copy = EvidenceStore(db_path=data / "evidence.db")
        assert copy.count("org_a") == 2 and copy.verify_chain("org_a")["valid"]
        copy.close()
        assert (data / "secrets" / "jwt_secret.key").read_text() == "old-secret"
        assert not (data / "certs" / "extra.pem").exists(), "files that were not in the backup must not linger"
        safety = Path(res["safety_copy"])
        assert (safety / "secrets" / "jwt_secret.key").read_text() == "changed-after-backup"
        assert EvidenceStore(db_path=safety / "evidence.db").count("org_a") == 3
        assert not list(data.glob(".restore-staging-*")), "staging folder must be cleaned up"

    def test_current_license_is_kept_unless_asked(self, data, monkeypatch):
        self._live(data, monkeypatch)
        (data / "veritas.vlic").write_text("OLD LICENSE IN BACKUP")
        path = backup.create_backup()
        self._stop_service()
        (data / "veritas.vlic").write_text("NEWER LICENSE")
        res = backup.restore_backup(path)
        assert res["success"] and "veritas.vlic" in res["skipped_files"]
        assert (data / "veritas.vlic").read_text() == "NEWER LICENSE"
        assert backup.restore_backup(path, restore_license=True)["success"]
        assert (data / "veritas.vlic").read_text() == "OLD LICENSE IN BACKUP"

    def test_license_is_restored_when_there_is_none(self, data, monkeypatch):
        self._live(data, monkeypatch)
        path = backup.create_backup()
        self._stop_service()
        (data / "veritas.vlic").unlink()
        assert backup.restore_backup(path)["success"]
        assert (data / "veritas.vlic").read_text() == "CURRENT LICENSE"

    def test_stale_sqlite_journal_files_are_removed(self, data, monkeypatch):
        self._live(data, monkeypatch)
        path = backup.create_backup()
        self._stop_service()
        for side in ("evidence.db-wal", "evidence.db-shm", "evidence.db-journal"):
            (data / side).write_bytes(b"stale")
        assert backup.restore_backup(path)["success"]
        assert not any((data / n).exists() for n in ("evidence.db-wal", "evidence.db-shm", "evidence.db-journal"))

    def test_refused_while_the_server_is_running(self, data, monkeypatch):
        self._live(data, monkeypatch)
        path = backup.create_backup()
        self._stop_service()
        before = self._snapshot(data)
        monkeypatch.setattr(backup, "_server_running", lambda: True)
        res = backup.restore_backup(path)
        assert not res["success"] and "running" in res["errors"][0].lower()
        assert self._snapshot(data) == before
        assert backup.restore_backup(path, force=True)["success"]

    def test_a_damaged_database_in_the_backup_is_refused_before_anything_changes(self, data, monkeypatch):
        self._live(data, monkeypatch)
        path = backup.create_backup()
        # rebuild the archive with a corrupt evidence.db but a manifest that matches it
        import hashlib, zipfile
        bad = data / "backups" / "veritas-backup-bad.zip"
        with zipfile.ZipFile(path) as zin, zipfile.ZipFile(bad, "w") as zout:
            manifest = json.loads(zin.read("backup_manifest.json"))
            for name in zin.namelist():
                blob = zin.read(name)
                if name == "evidence.db":
                    blob = b"this is not a database" * 50
                    manifest["files"][name] = {"type": "file", "sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)}
                if name != "backup_manifest.json":
                    zout.writestr(name, blob)
            zout.writestr("backup_manifest.json", json.dumps(manifest))
        assert backup.verify_backup(bad)[0], "checksums match, so only the integrity check can catch this"
        before = self._snapshot(data)
        res = backup.restore_backup(bad)
        assert not res["success"] and "damaged" in res["errors"][0]
        assert self._snapshot(data) == before, "live data must be untouched"

    def test_a_failure_in_the_middle_rolls_everything_back(self, data, monkeypatch):
        self._live(data, monkeypatch)
        path = backup.create_backup()
        (data / "secrets" / "jwt_secret.key").write_text("state-before-restore")
        before = self._snapshot(data)
        real = os.replace
        calls = {"n": 0}
        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError("disk full")
            return real(src, dst)
        monkeypatch.setattr(backup.os, "replace", flaky)
        res = backup.restore_backup(path)
        monkeypatch.setattr(backup.os, "replace", real)
        assert not res["success"] and "rolled back" in res["errors"][0]
        assert self._snapshot(data) == before, "the previous state must be put back exactly"

    def test_paths_that_escape_the_data_folder_are_refused(self, data):
        import hashlib, zipfile
        (data / "backups").mkdir(exist_ok=True)
        evil = data / "backups" / "veritas-backup-evil.zip"
        manifest = {"backup_version": "1", "files": {}}
        with zipfile.ZipFile(evil, "w") as z:
            for name, blob in {"evidence.db": b"x", "agents.db": b"x", "users.db": b"x", "../outside.txt": b"pwned",
                               "/etc/evil": b"pwned"}.items():
                z.writestr(name, blob)
                manifest["files"][name] = {"type": "file", "sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)}
            z.writestr("backup_manifest.json", json.dumps(manifest))
        res = backup.restore_backup(evil, target_root=data / "elsewhere")
        assert not res["success"] and "unexpected file paths" in res["errors"][0]
        assert not (data / "outside.txt").exists() and not (data / "elsewhere").exists()

    def test_a_backup_from_a_newer_release_is_refused(self, data, monkeypatch):
        self._live(data, monkeypatch)
        path = backup.create_backup()
        self._stop_service()
        monkeypatch.setattr(backup, "_app_version", lambda: "1.0.20")
        import zipfile, hashlib
        newer = data / "backups" / "veritas-backup-newer.zip"
        with zipfile.ZipFile(path) as zin, zipfile.ZipFile(newer, "w") as zout:
            manifest = json.loads(zin.read("backup_manifest.json")); manifest["app_version"] = "9.0.0"
            for name in zin.namelist():
                if name != "backup_manifest.json":
                    zout.writestr(name, zin.read(name))
            zout.writestr("backup_manifest.json", json.dumps(manifest))
        res = backup.restore_backup(newer)
        assert not res["success"] and "newer" in res["errors"][0]
        assert backup.restore_backup(newer, force=True)["success"]

    def test_dry_run_changes_nothing(self, data, monkeypatch):
        self._live(data, monkeypatch)
        path = backup.create_backup()
        (data / "secrets" / "jwt_secret.key").write_text("different")
        before = self._snapshot(data)
        res = backup.restore_backup(path, dry_run=True)
        assert res["success"] and "evidence.db" in res["restored_files"]
        assert self._snapshot(data) == before

    def test_dry_run_also_catches_a_damaged_database(self, data, monkeypatch):
        """The command checks with a dry run before it stops the service, so this must catch it."""
        self._live(data, monkeypatch)
        path = backup.create_backup()
        import hashlib, zipfile
        bad = data / "backups" / "veritas-backup-bad-dry.zip"
        with zipfile.ZipFile(path) as zin, zipfile.ZipFile(bad, "w") as zout:
            manifest = json.loads(zin.read("backup_manifest.json"))
            for name in zin.namelist():
                blob = zin.read(name)
                if name == "users.db":
                    blob = b"garbage" * 100
                    manifest["files"][name] = {"type": "file", "sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)}
                if name != "backup_manifest.json":
                    zout.writestr(name, blob)
            zout.writestr("backup_manifest.json", json.dumps(manifest))
        res = backup.restore_backup(bad, dry_run=True)
        assert not res["success"] and "damaged" in res["errors"][0]

    def test_a_corrupt_archive_is_refused(self, data, monkeypatch):
        self._live(data, monkeypatch)
        junk = data / "backups"; junk.mkdir(exist_ok=True)
        (junk / "veritas-backup-junk.zip").write_bytes(b"not a zip")
        res = backup.restore_backup(junk / "veritas-backup-junk.zip")
        assert not res["success"] and res["errors"]


class TestScheduledRun:
    def test_run_once_backs_up_checks_chains_and_records_it(self, data):
        status = maintenance.run_once()
        assert status["last_backup_ok"] is True
        assert (data / "backups" / status["last_backup_file"]).exists()
        assert status["chains_checked"] == 2 and status["chains_broken"] == []
        assert json.loads(maintenance.status_path().read_text())["last_backup_ok"] is True
        assert maintenance.assess()["status"] == "ok"

    def test_old_backups_are_pruned(self, data, monkeypatch):
        monkeypatch.setenv("VERITAS_BACKUP_KEEP", "3")
        t0 = datetime.now(timezone.utc)
        for i in range(5):
            maintenance.run_once(now=t0 + timedelta(seconds=i))
        names = sorted(p.name for p in (data / "backups").glob("veritas-backup-*.zip"))
        assert len(names) == 3
        assert names[-1].endswith((t0 + timedelta(seconds=4)).strftime("%Y%m%dT%H%M%SZ") + ".zip")

    def test_backup_directory_can_be_elsewhere(self, data, tmp_path_factory, monkeypatch):
        elsewhere = tmp_path_factory.mktemp("nfs")
        monkeypatch.setenv("VERITAS_BACKUP_DIR", str(elsewhere))
        status = maintenance.run_once()
        assert (elsewhere / status["last_backup_file"]).exists()

    def test_a_tampered_chain_is_reported_and_marks_the_system_unhealthy(self, data):
        conn = sqlite3.connect(data / "evidence.db")
        conn.execute("UPDATE evidence SET payload_json = ? WHERE tenant_id = 'org_b' AND row_index = "
                     "(SELECT MIN(row_index) FROM evidence WHERE tenant_id = 'org_b')", ('{"tampered": "data"}',))
        conn.commit(); conn.close()
        status = maintenance.run_once()
        assert status["chains_broken"] == ["org_b"]          # org_a is fine and still reported fine
        health = maintenance.assess()
        assert health["status"] == "error" and "org_b" in health["problem"]

    def test_a_failing_backup_is_recorded_not_hidden(self, data, monkeypatch):
        monkeypatch.setattr(backup, "create_backup", lambda path=None: (_ for _ in ()).throw(OSError("disk full")))
        status = maintenance.run_once()
        assert status["last_backup_ok"] is False and "disk full" in status["last_backup_error"]
        assert status["chains_checked"] == 2, "the chain check still runs when the backup fails"
        assert maintenance.assess()["status"] == "error"


class TestAssess:
    NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)

    def test_states(self, monkeypatch):
        monkeypatch.delenv("VERITAS_BACKUP_INTERVAL_HOURS", raising=False)
        recent = (self.NOW - timedelta(hours=20)).isoformat()
        old = (self.NOW - timedelta(days=4)).isoformat()
        assert maintenance.assess({}, self.NOW)["status"] == "pending"
        assert maintenance.assess({"last_backup_at": recent, "last_backup_ok": True}, self.NOW)["status"] == "ok"
        assert maintenance.assess({"last_backup_at": old, "last_backup_ok": True}, self.NOW)["status"] == "stale"
        assert maintenance.assess({"last_backup_at": recent, "last_backup_ok": False,
                                   "last_backup_error": "x"}, self.NOW)["status"] == "error"
        assert maintenance.assess({"last_backup_at": recent, "last_backup_ok": True,
                                   "chains_broken": ["a"]}, self.NOW)["status"] == "error"
        monkeypatch.setenv("VERITAS_BACKUP_INTERVAL_HOURS", "0")
        assert maintenance.assess({}, self.NOW)["status"] == "disabled"

    def test_settings_survive_garbage(self, monkeypatch):
        monkeypatch.setenv("VERITAS_BACKUP_INTERVAL_HOURS", "soon")
        monkeypatch.setenv("VERITAS_BACKUP_KEEP", "-4")
        assert maintenance.interval_hours() == 24
        assert maintenance.keep_count() == 1


class TestSchedule:
    def test_runs_after_the_first_delay_and_can_be_stopped(self, data, monkeypatch):
        monkeypatch.setenv("VERITAS_BACKUP_INTERVAL_HOURS", "1")
        stop = maintenance.start(first_delay=0.2)
        try:
            for _ in range(100):
                if maintenance.read_status().get("last_backup_ok"):
                    break
                time.sleep(0.1)
            assert maintenance.read_status().get("last_backup_ok") is True
        finally:
            stop.set()

    def test_off_when_interval_is_zero(self, data, monkeypatch):
        monkeypatch.setenv("VERITAS_BACKUP_INTERVAL_HOURS", "0")
        stop = maintenance.start(first_delay=0.1)
        time.sleep(0.5)
        stop.set()
        assert not maintenance.read_status()

    def test_a_restart_does_not_trigger_an_immediate_second_backup(self, data, monkeypatch):
        monkeypatch.setenv("VERITAS_BACKUP_INTERVAL_HOURS", "24")
        maintenance.run_once()
        before = maintenance.read_status()["last_backup_file"]
        stop = maintenance.start(first_delay=0.1)
        time.sleep(0.6)
        stop.set()
        assert maintenance.read_status()["last_backup_file"] == before


# ── TLS certificate installation ───────────────────────────────────────────
def _make_pair(tmp: Path, name="srv", days=90, cn="veritas.example.com", sans=("veritas.example.com", "10.0.0.5"),
               start_offset=-1):
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    names = [x509.IPAddress(ipaddress.ip_address(s)) if s[0].isdigit() else x509.DNSName(s) for s in sans]
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + timedelta(days=start_offset)).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(names), critical=False).sign(key, hashes.SHA256()))
    c, k = tmp / f"{name}.crt", tmp / f"{name}.key"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    return c, k


@pytest.fixture
def certdir(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "data"))
    for var in ("VERITAS_TLS_CERT", "VERITAS_TLS_KEY"):
        monkeypatch.delenv(var, raising=False)
    (tmp_path / "in").mkdir()
    return tmp_path / "in"


class TestInstallCertificate:
    def test_installs_a_valid_pair(self, certdir):
        crt, key = _make_pair(certdir)
        info = tls.install_certificate(crt, key)
        assert info["names"] == ["veritas.example.com", "10.0.0.5"]
        assert 85 <= info["days_remaining"] <= 90
        assert tls.cert_path().read_bytes() == crt.read_bytes()
        assert tls.key_path().read_bytes() == key.read_bytes()
        if sys.platform != "win32":
            assert (tls.key_path().stat().st_mode & 0o077) == 0, "private key must be owner-only"
        assert 85 <= tls.cert_days_remaining() <= 90

    def test_previous_certificate_is_kept(self, certdir):
        old_c, old_k = _make_pair(certdir, "old")
        tls.install_certificate(old_c, old_k)
        new_c, new_k = _make_pair(certdir, "new")
        info = tls.install_certificate(new_c, new_k)
        kept = list(tls.cert_path().parent.glob("server.crt.2*"))
        assert info["backup"] and len(kept) == 1 and kept[0].read_bytes() == old_c.read_bytes()

    def test_mismatched_key_changes_nothing(self, certdir):
        a_c, a_k = _make_pair(certdir, "a")
        b_c, b_k = _make_pair(certdir, "b")
        tls.install_certificate(a_c, a_k)
        with pytest.raises(tls.CertificateError, match="does not belong"):
            tls.install_certificate(a_c, b_k)
        assert tls.cert_path().read_bytes() == a_c.read_bytes()

    def test_expired_not_yet_valid_garbage_and_passphrase_are_refused(self, certdir):
        old_c, old_k = _make_pair(certdir, "expired", days=-1, start_offset=-30)
        with pytest.raises(tls.CertificateError, match="expired"):
            tls.install_certificate(old_c, old_k)
        fut_c, fut_k = _make_pair(certdir, "future", days=60, start_offset=10)
        with pytest.raises(tls.CertificateError, match="not valid until"):
            tls.install_certificate(fut_c, fut_k)
        junk = certdir / "junk.pem"; junk.write_text("hello")
        good_c, good_k = _make_pair(certdir, "good")
        with pytest.raises(tls.CertificateError, match="not a PEM certificate"):
            tls.install_certificate(junk, good_k)
        with pytest.raises(tls.CertificateError, match="key"):
            tls.install_certificate(good_c, junk)
        with pytest.raises(tls.CertificateError, match="Cannot read"):
            tls.install_certificate(certdir / "missing.crt", good_k)
        assert not tls.cert_path().exists(), "nothing may be installed when a check fails"

    def test_placeholder_names_are_refused(self, certdir):
        crt, key = _make_pair(certdir, "ph", cn="<HOST>", sans=("<HOST>",))
        with pytest.raises(tls.CertificateError, match="placeholder"):
            tls.install_certificate(crt, key)
        assert not tls.cert_path().exists()

    def test_warns_when_the_certificate_does_not_cover_this_machine(self, certdir, monkeypatch):
        monkeypatch.setattr(tls.socket, "gethostname", lambda: "jarvis")
        other_c, other_k = _make_pair(certdir, "other", sans=("veritas.example.com",))
        assert any("jarvis" in w for w in tls.install_certificate(other_c, other_k)["warnings"])
        mine_c, mine_k = _make_pair(certdir, "mine", sans=("jarvis", "localhost"))
        assert tls.install_certificate(mine_c, mine_k)["warnings"] == []
        wild_c, wild_k = _make_pair(certdir, "wild", sans=("*.corp.example",))
        monkeypatch.setattr(tls.socket, "gethostname", lambda: "veritas.corp.example")
        assert tls.install_certificate(wild_c, wild_k)["warnings"] == []

    def test_passphrase_protected_key_gets_a_clear_message(self, certdir):
        from cryptography.hazmat.primitives import serialization
        crt, key = _make_pair(certdir, "pp")
        k = serialization.load_pem_private_key(key.read_bytes(), None)
        key.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.BestAvailableEncryption(b"secret")))
        with pytest.raises(tls.CertificateError, match="passphrase"):
            tls.install_certificate(crt, key)

    def test_chain_file_is_installed_whole(self, certdir):
        leaf_c, leaf_k = _make_pair(certdir, "leaf")
        inter_c, _ = _make_pair(certdir, "inter", cn="Intermediate CA")
        chain = certdir / "chain.pem"
        chain.write_bytes(leaf_c.read_bytes() + inter_c.read_bytes())
        tls.install_certificate(chain, leaf_k)
        assert tls.cert_path().read_bytes().count(b"BEGIN CERTIFICATE") == 2

    def test_server_uses_the_installed_files(self, certdir, monkeypatch):
        monkeypatch.setenv("VERITAS_TLS", "auto")      # CI runs with TLS switched off
        crt, key = _make_pair(certdir)
        tls.install_certificate(crt, key)
        params = tls.get_ssl_params()
        assert params == {"ssl_certfile": str(tls.cert_path()), "ssl_keyfile": str(tls.key_path())}


class TestCommandLine:
    def test_install_cert_flag(self, certdir, monkeypatch, capsys):
        import run_pipeline
        crt, key = _make_pair(certdir)
        monkeypatch.setattr(sys, "argv", ["veritas", "--install-cert", str(crt), str(key)])
        run_pipeline.main()
        out = capsys.readouterr().out
        assert "Certificate installed" in out and "veritas.example.com" in out
        assert tls.cert_path().exists()

    def test_install_cert_flag_reports_errors_and_exits_1(self, certdir, monkeypatch, capsys):
        import run_pipeline
        crt, _ = _make_pair(certdir, "x")
        other_c, other_k = _make_pair(certdir, "y")
        monkeypatch.setattr(sys, "argv", ["veritas", "--install-cert", str(crt), str(other_k)])
        with pytest.raises(SystemExit) as exc:
            run_pipeline.main()
        assert exc.value.code == 1
        assert "does not belong" in capsys.readouterr().err
        assert not tls.cert_path().exists()


# ── what the dashboard reads ───────────────────────────────────────────────
class TestHealthEndpoint:
    @pytest.fixture
    def admin(self, data, monkeypatch):
        from fastapi.testclient import TestClient
        import agent_store.store as agent_store_module
        import user_store.store as user_store_module
        from agent_store.store import reset_agent_store
        from api.auth import _hash_password
        from dashboard.server import app
        from rate_limit import _limiter
        from user_store.models import UserRole
        from user_store.store import get_user_store, reset_user_store
        monkeypatch.setattr(agent_store_module, "_DEFAULT_DB_PATH", data / "agents.db")
        monkeypatch.setattr(user_store_module, "_DEFAULT_DB_PATH", data / "users2.db")
        monkeypatch.setenv("VERITAS_SECURE_COOKIES", "false")
        monkeypatch.setenv("VERITAS_JWT_SECRET", "test-jwt-secret-for-unit-tests-only")
        reset_agent_store(); reset_user_store(); _limiter._windows.clear()
        get_user_store().create_user("boss", "boss@example.com", _hash_password("Adm1n-Strong#Pass"), UserRole.SUPER_ADMIN)
        get_user_store().create_user("view", "view@example.com", _hash_password("Adm1n-Strong#Pass"), UserRole.VIEWER)
        yield lambda who: _login(TestClient(app, raise_server_exceptions=False), who)
        reset_agent_store(); reset_user_store(); _limiter._windows.clear()

    def test_super_admin_sees_backup_and_chain_state(self, admin):
        c = admin("boss")
        before = c.get("/api/system/health").json()["checks"]["maintenance"]
        assert before["status"] == "pending"
        maintenance.run_once()
        after = c.get("/api/system/health").json()
        assert after["checks"]["maintenance"]["status"] == "ok"
        assert after["checks"]["maintenance"]["chains_checked"] == 2

    def test_a_broken_chain_makes_health_report_unhealthy(self, admin, data):
        conn = sqlite3.connect(data / "evidence.db")
        conn.execute("UPDATE evidence SET payload_json = ? WHERE tenant_id = 'org_a'", ('{"tampered": "data"}',))
        conn.commit(); conn.close()
        maintenance.run_once()
        body = admin("boss").get("/api/system/health").json()
        assert body["healthy"] is False and body["checks"]["maintenance"]["status"] == "error"

    def test_other_roles_do_not_see_maintenance_details(self, admin):
        maintenance.run_once()
        checks = admin("view").get("/api/system/health").json()["checks"]
        assert "maintenance" not in checks

    def test_tls_expiry_is_reported(self, admin, certdir, monkeypatch):
        crt, key = _make_pair(certdir, days=10)
        monkeypatch.setenv("VERITAS_TLS_CERT", str(crt)); monkeypatch.setenv("VERITAS_TLS_KEY", str(key))
        monkeypatch.setenv("VERITAS_TLS", "auto")
        tlsinfo = admin("boss").get("/api/system/health").json()["checks"]["tls"]
        assert tlsinfo["status"] == "expiring" and 8 <= tlsinfo["days_remaining"] <= 10


def _login(client, who):
    r = client.post("/api/auth/login", data={"username": who, "password": "Adm1n-Strong#Pass"})
    assert r.status_code == 200, r.text
    return client


class TestBackupsAreSingleFiles:
    def test_a_backup_of_a_write_ahead_log_database_holds_one_file_and_restores_without_leftovers(self, data, monkeypatch, tmp_path_factory):
        import zipfile
        # the live evidence database uses write-ahead logging
        assert sqlite3.connect(data / "evidence.db").execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        path = backup.create_backup()
        names = zipfile.ZipFile(path).namelist()
        assert "evidence.db" in names and not any(n.endswith(("-wal", "-shm")) for n in names)
        target = tmp_path_factory.mktemp("restore2")
        assert backup.restore_backup(path, target_root=target)["success"]
        assert not any((target / n).exists() for n in ("evidence.db-wal", "evidence.db-shm"))
        assert sqlite3.connect(target / "evidence.db").execute("PRAGMA journal_mode").fetchone()[0] == "delete"

    def test_a_log_file_left_by_a_crash_is_kept_in_the_safety_copy(self, data, monkeypatch):
        """After a crash the newest records may only be in the -wal file; a restore must not lose them."""
        self._live = TestRestore._live.__get__(self)
        self._stop_service = TestRestore._stop_service.__get__(self)
        self._live(data, monkeypatch)
        path = backup.create_backup()
        self._stop_service()
        (data / "evidence.db-wal").write_bytes(b"committed but not yet in the main file")
        res = backup.restore_backup(path)
        assert res["success"], res
        kept = Path(res["safety_copy"]) / "evidence.db-wal"
        assert kept.read_bytes() == b"committed but not yet in the main file"
        assert not (data / "evidence.db-wal").exists()          # and the restored database starts clean
