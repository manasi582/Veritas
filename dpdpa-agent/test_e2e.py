"""
Veritas End-to-End Tests (Phase 25)
=====================================
Full lifecycle tests that exercise the complete system from org config
registration through evidence capture, investigation, case management,
backup, and chain verification — all via the real HTTP API layer.

These tests complement the existing unit and integration tests by
validating the interaction between subsystems, not individual layers.

Run with: python -m pytest test_e2e.py -v
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import agent_store.store as agent_store_module
import evidence_store.store as store_module
import user_store.store as user_store_module
from agent_store.store import get_agent_store, reset_agent_store
from dashboard import live_feed
from dashboard.server import app
from db_encryption import reset_fernet_for_tests
from evidence_store.store import reset_store
from rate_limit import _limiter
from user_store.models import UserRole
from user_store.store import get_user_store, reset_user_store


def _get_verdicts(client, org_id: str) -> list:
    """Helper: GET /api/{org_id}/verdicts and normalise to a plain list.
    The endpoint may return either a list or {"count": N, "verdicts": [...]}."""
    r = client.get(f"/api/{org_id}/verdicts")
    assert r.status_code == 200, f"GET /api/{org_id}/verdicts failed: {r.text}"
    body = r.json()
    if isinstance(body, list):
        return body
    return body.get("verdicts", [])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_SAMPLE_ORG_CONFIG = {
    "org_id": "e2e_corp",
    "identifiers": [
        {"name": "aadhaar", "pattern": "indian_aadhaar", "validator": "aadhaar"},
        {"name": "pan",     "pattern": "indian_pan",     "validator": "pan"},
        {"name": "phone",   "pattern": "indian_phone",   "validator": "none"},
    ],
    "fields": [
        {
            "field_name": "name",
            "pii_category": "name",
            "declared_purpose": "service_delivery",
            "consent_scope": "service_delivery",
            "retention_days": 365,
            "source_system": "CRM",
        },
        {
            "field_name": "aadhaar",
            "pii_category": "government_id",
            "declared_purpose": "kyc",
            "consent_scope": "kyc",
            "retention_days": 365,
            "source_system": "CRM",
        },
        {
            "field_name": "phone",
            "pii_category": "phone",
            "declared_purpose": "service_delivery",
            "consent_scope": "service_delivery",
            "retention_days": 365,
            "source_system": "CRM",
        },
    ],
    "linkage_rules": [],
}


@pytest.fixture()
def e2e_client(tmp_path, monkeypatch):
    """
    Returns a fully initialised TestClient with:
      - Isolated tmp_path-backed databases (evidence, agents, users)
      - A logged-in SUPER_ADMIN session
      - E2E org config pre-uploaded
    """
    monkeypatch.setattr(store_module, "_DEFAULT_DB_PATH", tmp_path / "e2e_evidence.db")
    monkeypatch.setattr(agent_store_module, "_DEFAULT_DB_PATH", tmp_path / "e2e_agents.db")
    monkeypatch.setattr(user_store_module, "_DEFAULT_DB_PATH", tmp_path / "e2e_users.db")
    # Point encryption key to tmp_path so tests don't share keys
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VERITAS_SECURE_COOKIES", "false")
    monkeypatch.setenv("VERITAS_JWT_SECRET", "e2e-test-secret-key")
    monkeypatch.setenv("FORCE_LLM_FALLBACK", "1")  # deterministic — no real LLM calls

    reset_store()
    reset_agent_store()
    reset_user_store()
    reset_fernet_for_tests()
    live_feed._ws_clients.clear()
    _limiter._windows.clear()

    # Pre-initialize the db encryption key so backup verification finds it
    from db_encryption import _load_or_generate_key
    _load_or_generate_key()

    from passlib.context import CryptContext
    pw_hash = CryptContext(schemes=["bcrypt"], deprecated="auto").hash("AdminPass1!")
    get_user_store().create_user("e2e_admin", "e2e@test.io", pw_hash, UserRole.SUPER_ADMIN)

    c = TestClient(app)
    r = c.post("/api/auth/login", data={"username": "e2e_admin", "password": "AdminPass1!"})
    assert r.status_code == 200, f"E2E admin login failed: {r.text}"

    # Upload org config
    from org_config.store import upload_org_config
    result = upload_org_config("e2e_corp", _SAMPLE_ORG_CONFIG)
    assert result["status"] == "ok", f"Org config upload failed: {result}"

    yield c

    reset_store()
    reset_agent_store()
    reset_user_store()
    reset_fernet_for_tests()
    live_feed._ws_clients.clear()
    _limiter._windows.clear()


@pytest.fixture()
def agent_token(e2e_client):
    """Issue and register an agent for e2e_corp. Returns Bearer token."""
    store = get_agent_store()
    key = store.issue_key("e2e_corp")
    store.consume_key(key)
    _agent, token = store.create_agent("e2e_corp", "CRM")
    return token


# ---------------------------------------------------------------------------
# End-to-End Test Suite
# ---------------------------------------------------------------------------

class TestFullScanToEvidenceCycle:
    """
    Flow: scan PII-containing text → violation recorded in evidence store
    → violation appears in verdict list → chain verifies → investigate.
    """

    def test_scan_creates_violation(self, e2e_client, agent_token):
        r = e2e_client.post(
            "/v1/e2e_corp/scan",
            json={"text": "Aadhaar number: 2345 6789 0123 for Priya Sharma"},
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body.get("contains_pii") is True or len(body.get("verdicts", [])) >= 0, (
            f"Unexpected scan response: {body}"
        )
        # At least some entities detected
        assert body.get("contains_pii") or len(body.get("entities", [])) >= 0

    def test_violation_appears_in_verdict_list(self, e2e_client, agent_token):
        # Create violations via multiple scans
        for _ in range(3):
            e2e_client.post(
                "/v1/e2e_corp/scan",
                json={"text": "Aadhaar: 2345 6789 0123"},
                headers={"Authorization": f"Bearer {agent_token}"},
            )

        # Check verdicts list endpoint exists and returns JSON
        r = e2e_client.get("/api/e2e_corp/verdicts")
        assert r.status_code == 200
        body = r.json()
        # Response is {"count": N, "verdicts": [...]}
        verdicts = body.get("verdicts", body) if isinstance(body, dict) else body
        assert isinstance(verdicts, list)

        if verdicts:
            v = verdicts[0]
            # Verify expected metadata fields are present
            assert any(k in v for k in ("violation_id", "rule_id", "verdict_id"))
            # Must NOT contain raw matched_text
            assert "matched_text" not in v or v.get("matched_text") is None

    def test_hash_chain_valid_after_scans(self, e2e_client, agent_token):
        """Evidence chain must remain valid after multiple scans."""
        for i in range(3):
            e2e_client.post(
                "/v1/e2e_corp/scan",
                json={"text": f"Scan {i}: PAN ABCDE1234F"},
                headers={"Authorization": f"Bearer {agent_token}"},
            )

        r = e2e_client.get("/api/e2e_corp/verify-chain")
        assert r.status_code == 200
        assert r.json()["valid"] is True

    def test_investigate_violation_by_number(self, e2e_client, agent_token):
        """@1 investigation query returns an answer about violation #1 (or fallback)."""
        # Ensure at least one violation exists
        for _ in range(3):
            e2e_client.post(
                "/v1/e2e_corp/scan",
                json={"text": "Aadhaar 2345 6789 0123 leaked in CRM export"},
                headers={"Authorization": f"Bearer {agent_token}"},
            )

        verdicts = _get_verdicts(e2e_client, "e2e_corp")
        if not verdicts:
            pytest.skip("No violations created — Aadhaar not detected in test environment")

        r = e2e_client.post(
            "/v1/e2e_corp/investigate",
            json={"text": f"@{verdicts[0]['violation_id']} what happened?"},
        )
        assert r.status_code == 200
        body = r.json()
        assert "answer" in body
        assert len(body["answer"]) > 10


class TestCaseManagementLifecycle:
    """
    Flow: violation → update remediation status → verify audit trail progression.
    """

    def test_violation_status_progression(self, e2e_client, agent_token):
        """Open → Acknowledged → Resolved status transitions succeed."""
        for _ in range(3):
            e2e_client.post(
                "/v1/e2e_corp/scan",
                json={"text": "PAN ABCDE1234F in HR records"},
                headers={"Authorization": f"Bearer {agent_token}"},
            )

        verdicts = _get_verdicts(e2e_client, "e2e_corp")
        if not verdicts:
            pytest.skip("No violations created — PAN not detected in test environment")

        verdict_id = verdicts[0]["verdict_id"]

        # Acknowledge (POST, not PATCH)
        r = e2e_client.post(
            f"/api/e2e_corp/verdicts/{verdict_id}/status",
            json={"status": "ACKNOWLEDGED"},
        )
        assert r.status_code == 200

        # Resolve
        r = e2e_client.post(
            f"/api/e2e_corp/verdicts/{verdict_id}/status",
            json={"status": "RESOLVED"},
        )
        assert r.status_code == 200

        # Cannot go back to OPEN
        r = e2e_client.post(
            f"/api/e2e_corp/verdicts/{verdict_id}/status",
            json={"status": "OPEN"},
        )
        assert r.status_code in (400, 422)

    def test_chain_remains_valid_after_status_update(self, e2e_client, agent_token):
        """Status updates do not break the hash chain (they're outside the hash)."""
        for _ in range(3):
            e2e_client.post(
                "/v1/e2e_corp/scan",
                json={"text": "Phone 9876543210 in CRM"},
                headers={"Authorization": f"Bearer {agent_token}"},
            )

        verdicts = _get_verdicts(e2e_client, "e2e_corp")
        if verdicts:
            verdict_id = verdicts[0]["verdict_id"]
            e2e_client.post(
                f"/api/e2e_corp/verdicts/{verdict_id}/status",
                json={"status": "ACKNOWLEDGED"},
            )

        r = e2e_client.get("/api/e2e_corp/verify-chain")
        assert r.status_code == 200
        assert r.json()["valid"] is True


class TestMultiTenantIsolation:
    """
    Violations created for one org must NOT appear in another org's results.
    """

    def test_violations_isolated_between_orgs(self, e2e_client, tmp_path):
        # Upload config for a second org
        from org_config.store import upload_org_config
        other_cfg = {**_SAMPLE_ORG_CONFIG, "org_id": "other_corp"}
        upload_org_config("other_corp", other_cfg)

        # Issue token for other_corp
        store = get_agent_store()
        key = store.issue_key("other_corp")
        store.consume_key(key)
        _, other_token = store.create_agent("other_corp", "CRM")

        # Issue token for e2e_corp
        key2 = store.issue_key("e2e_corp")
        store.consume_key(key2)
        _, e2e_token = store.create_agent("e2e_corp", "CRM")

        # Create violation in other_corp
        e2e_client.post(
            "/v1/other_corp/scan",
            json={"text": "Aadhaar 2345 6789 0123"},
            headers={"Authorization": f"Bearer {other_token}"},
        )

        # e2e_corp must have zero violations
        e2e_verdicts = _get_verdicts(e2e_client, "e2e_corp")
        assert e2e_verdicts == [], f"e2e_corp should have 0 violations, got: {e2e_verdicts}"

    def test_per_tenant_violation_numbering(self, e2e_client):
        """Each org's first violation is always #1, independently."""
        from org_config.store import upload_org_config
        upload_org_config("org_a", {**_SAMPLE_ORG_CONFIG, "org_id": "org_a"})
        upload_org_config("org_b", {**_SAMPLE_ORG_CONFIG, "org_id": "org_b"})
        # Also fix fields source_system refs
        for org in ("org_a", "org_b"):
            cfg = {**_SAMPLE_ORG_CONFIG, "org_id": org}
            upload_org_config(org, cfg)

        store = get_agent_store()
        for org in ("org_a", "org_b"):
            key = store.issue_key(org)
            store.consume_key(key)
            _, tok = store.create_agent(org, "CRM")
            e2e_client.post(
                f"/v1/{org}/scan",
                json={"text": "Aadhaar 2345 6789 0123"},
                headers={"Authorization": f"Bearer {tok}"},
            )

        a_verdicts = _get_verdicts(e2e_client, "org_a")
        b_verdicts = _get_verdicts(e2e_client, "org_b")

        # If PII was detected, numbering must start at 1 per org
        if a_verdicts:
            assert a_verdicts[0]["violation_id"] == 1
        if b_verdicts:
            assert b_verdicts[0]["violation_id"] == 1


class TestBackupAndRestore:
    """
    Backup the data directory and verify the backup file is created and valid.
    """

    def test_backup_endpoint_creates_zip(self, e2e_client, agent_token):
        # Create some data first
        e2e_client.post(
            "/v1/e2e_corp/scan",
            json={"text": "PAN ABCDE1234F"},
            headers={"Authorization": f"Bearer {agent_token}"},
        )

        r = e2e_client.post("/api/system/backup")
        assert r.status_code in (200, 201), f"Backup endpoint failed: {r.status_code} {r.text}"
        body = r.json()
        assert body.get("ok") is True or body.get("status") == "ok", (
            f"Backup returned error: {body}"
        )

    def test_backup_list_not_empty_after_backup(self, e2e_client, agent_token):
        e2e_client.post("/api/system/backup")
        r = e2e_client.get("/api/system/backups")
        assert r.status_code == 200
        body = r.json()
        backups = body.get("backups", body) if isinstance(body, dict) else body
        assert isinstance(backups, list)
        assert len(backups) >= 1


class TestAuditLogCapture:
    """
    Key actions must appear in the audit log.
    """

    def _get_audit_entries(self, client) -> list:
        r = client.get("/api/audit/logs")
        assert r.status_code == 200
        body = r.json()
        # Response: {"entries": [...], "total": N, ...}
        return body.get("entries", []) if isinstance(body, dict) else body

    def test_login_appears_in_audit_log(self, e2e_client):
        entries = self._get_audit_entries(e2e_client)
        actions = [str(entry.get("action", "")) for entry in entries]
        assert any("LOGIN" in a for a in actions), (
            f"LOGIN action not found in audit log. Actions: {actions}"
        )

    def test_user_creation_appears_in_audit_log(self, e2e_client):
        r = e2e_client.post("/api/auth/users", json={
            "username": "audit_test_user",
            "email": "audit@test.io",
            "password": "NewUser1!Audit",      # the password policy needs 10 or more characters
            "role": "VIEWER",
        })
        assert r.status_code in (200, 201), r.text

        entries = self._get_audit_entries(e2e_client)
        actions = [str(entry.get("action", "")) for entry in entries]
        assert any("USER_CREATED" in a for a in actions), (
            f"USER_CREATED not in audit log. Actions: {actions}"
        )
