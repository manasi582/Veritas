"""The audit pack: its contents, its manifest, who may fetch it, and that it never carries a raw personal value."""
import hashlib
import io
import json
import zipfile

import pytest

from api.test_anchors_api import ORG, client, isolated, seed  # noqa: F401  (fixtures)
from user_store.models import UserRole


def fetch(role=UserRole.AUDITOR, name="aud"):
    c = client(role, name)
    return c.get(f"/v1/{ORG}/audit-pack")


def test_pack_holds_the_files_an_auditor_needs():
    seed(3)
    r = fetch()
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    assert {"evidence.jsonl", "checkpoints.jsonl", "veritas.pub", "summary.json", "SUMMARY.md", "VERIFY.md",
            "verify.sh", "verify.bat", "MANIFEST.sha256"} <= names
    head = json.loads(z.read("evidence.jsonl").splitlines()[0])
    assert head["record_count"] == 3
    s = json.loads(z.read("summary.json"))
    assert s["organization"] == ORG and s["chain"]["records"] == 3 and s["chain"]["internal_check"]["valid"] is True


def test_manifest_matches_every_other_file():
    seed(2)
    z = zipfile.ZipFile(io.BytesIO(fetch().content))
    listed = dict(line.split("  ", 1)[::-1] for line in z.read("MANIFEST.sha256").decode().splitlines())
    assert set(listed) == set(z.namelist()) - {"MANIFEST.sha256"}
    for name, digest in listed.items():
        assert hashlib.sha256(z.read(name)).hexdigest() == digest


def test_summary_says_what_the_pack_does_not_prove():
    seed(1)
    text = zipfile.ZipFile(io.BytesIO(fetch().content)).read("SUMMARY.md").decode()
    assert "does not prove" in text and "legal advice" in text and "anchoring is not configured" in text


def test_pack_is_audit_logged_and_empty_org_is_404():
    c = client(UserRole.AUDITOR, "aud")
    assert c.get(f"/v1/{ORG}/audit-pack").status_code == 404
    seed(1)
    assert c.get(f"/v1/{ORG}/audit-pack").status_code == 200


def test_roles_without_audit_access_are_refused():
    seed(1)
    assert fetch(UserRole.VIEWER, "viewer").status_code == 403


def test_verifier_binaries_are_added_when_a_folder_is_named(tmp_path, monkeypatch):
    seed(1)
    (tmp_path / "veritas-verify_1.0_linux_amd64").write_bytes(b"\x7fELF-not-real")
    monkeypatch.setenv("VERITAS_VERIFIER_DIR", str(tmp_path))
    z = zipfile.ZipFile(io.BytesIO(fetch().content))
    assert "veritas-verify_1.0_linux_amd64" in z.namelist()
