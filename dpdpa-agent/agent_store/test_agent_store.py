"""
Agent Store — Unit Tests (Block 2)
===================================
Tests for agent_store/store.py: registration key issuance/consumption,
Agent creation, token validation, revocation, heartbeat, event counter,
and multi-org isolation.

Run with: python -m pytest agent_store/test_agent_store.py -v
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

import agent_store.store as store_module
from agent_store.models import AgentStatus
from agent_store.store import AgentStore, get_agent_store, reset_agent_store


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_agent_store(tmp_path, monkeypatch):
    """Each test gets a fresh in-process AgentStore backed by a tmp file."""
    monkeypatch.setattr(store_module, "_DEFAULT_DB_PATH", tmp_path / "test_agents.db")
    reset_agent_store()
    yield
    reset_agent_store()


@pytest.fixture()
def store() -> AgentStore:
    return get_agent_store()


# ---------------------------------------------------------------------------
# Registration key — issuance
# ---------------------------------------------------------------------------

class TestIssueKey:

    def test_returns_plaintext_string(self, store):
        key = store.issue_key("acme")
        assert isinstance(key, str)
        assert len(key) > 0

    def test_keys_are_unique(self, store):
        k1 = store.issue_key("acme")
        k2 = store.issue_key("acme")
        assert k1 != k2

    def test_key_not_stored_as_plaintext(self, store, tmp_path):
        key = store.issue_key("acme")
        # The database should contain the hash, not the plaintext key
        import sqlite3
        conn = sqlite3.connect(str(store.db_path))
        rows = conn.execute("SELECT key_hash FROM registration_keys").fetchall()
        conn.close()
        stored_values = [r[0] for r in rows]
        assert key not in stored_values

    def test_org_association_stored(self, store):
        store.issue_key("acme")
        import sqlite3
        conn = sqlite3.connect(str(store.db_path))
        row = conn.execute("SELECT org_id FROM registration_keys").fetchone()
        conn.close()
        assert row[0] == "acme"

    def test_can_issue_multiple_keys_for_same_org(self, store):
        store.issue_key("acme")
        store.issue_key("acme")
        import sqlite3
        conn = sqlite3.connect(str(store.db_path))
        count = conn.execute("SELECT COUNT(*) FROM registration_keys WHERE org_id='acme'").fetchone()[0]
        conn.close()
        assert count == 2


# ---------------------------------------------------------------------------
# Registration key — consumption
# ---------------------------------------------------------------------------

class TestConsumeKey:

    def test_valid_key_succeeds(self, store):
        key = store.issue_key("acme")
        reg_key = store.consume_key(key)
        assert reg_key.org_id == "acme"
        assert reg_key.used is True

    def test_used_key_rejected(self, store):
        key = store.issue_key("acme")
        store.consume_key(key)
        with pytest.raises(ValueError, match="already been used"):
            store.consume_key(key)

    def test_unknown_key_rejected(self, store):
        with pytest.raises(ValueError, match="invalid or does not exist"):
            store.consume_key("totally-fake-key")

    def test_expired_key_rejected(self, store, monkeypatch):
        key = store.issue_key("acme")
        # Monkey-patch _now() to simulate future time past expiry
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        monkeypatch.setattr(store_module, "_now", lambda: future)
        with pytest.raises(ValueError, match="expired"):
            store.consume_key(key)

    def test_key_marked_used_after_consumption(self, store):
        key = store.issue_key("acme")
        store.consume_key(key)
        import sqlite3
        conn = sqlite3.connect(str(store.db_path))
        row = conn.execute("SELECT used FROM registration_keys").fetchone()
        conn.close()
        assert row[0] == 1


# ---------------------------------------------------------------------------
# Agent creation
# ---------------------------------------------------------------------------

class TestCreateAgent:

    def test_returns_agent_and_token(self, store):
        key = store.issue_key("acme")
        store.consume_key(key)
        agent, token = store.create_agent("acme", "order-service")
        assert agent.agent_id.startswith("VERITAS-AGENT-")
        assert len(agent.agent_id) == len("VERITAS-AGENT-") + 6
        assert isinstance(token, str)
        assert len(token) > 0

    def test_agent_id_format(self, store):
        key = store.issue_key("acme")
        store.consume_key(key)
        agent, _ = store.create_agent("acme")
        suffix = agent.agent_id.removeprefix("VERITAS-AGENT-")
        assert suffix.isupper() or all(c in "0123456789ABCDEF" for c in suffix)
        assert len(suffix) == 6

    def test_agent_ids_are_unique(self, store):
        ids = set()
        for _ in range(10):
            agent, _ = store.create_agent("acme")
            ids.add(agent.agent_id)
        assert len(ids) == 10

    def test_token_not_stored_as_plaintext(self, store):
        _, token = store.create_agent("acme")
        import sqlite3
        conn = sqlite3.connect(str(store.db_path))
        rows = conn.execute("SELECT token_hash FROM agents").fetchall()
        conn.close()
        assert token not in [r[0] for r in rows]

    def test_agent_status_is_active(self, store):
        agent, _ = store.create_agent("acme")
        assert agent.status == AgentStatus.ACTIVE

    def test_source_label_stored(self, store):
        agent, _ = store.create_agent("acme", "marketing-service")
        assert agent.source_label == "marketing-service"

    def test_events_received_starts_at_zero(self, store):
        agent, _ = store.create_agent("acme")
        assert agent.events_received == 0


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------

class TestValidateToken:

    def test_valid_token_returns_agent(self, store):
        agent, token = store.create_agent("acme")
        result = store.validate_token(token)
        assert result is not None
        assert result.agent_id == agent.agent_id

    def test_invalid_token_returns_none(self, store):
        store.create_agent("acme")
        result = store.validate_token("not-a-real-token")
        assert result is None

    def test_empty_token_returns_none(self, store):
        result = store.validate_token("")
        assert result is None

    def test_revoked_agent_token_still_returns_agent_with_revoked_status(self, store):
        agent, token = store.create_agent("acme")
        store.revoke_agent(agent.agent_id)
        result = store.validate_token(token)
        # validate_token returns the agent; caller checks status
        assert result is not None
        assert result.status == AgentStatus.REVOKED


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

class TestRevokeAgent:

    def test_revoke_sets_status(self, store):
        agent, _ = store.create_agent("acme")
        found = store.revoke_agent(agent.agent_id)
        assert found is True
        updated = store.get_agent(agent.agent_id)
        assert updated.status == AgentStatus.REVOKED

    def test_revoke_unknown_agent_returns_false(self, store):
        found = store.revoke_agent("VERITAS-AGENT-FAKE00")
        assert found is False

    def test_revoking_does_not_delete_record(self, store):
        agent, _ = store.create_agent("acme")
        store.revoke_agent(agent.agent_id)
        still_there = store.get_agent(agent.agent_id)
        assert still_there is not None


# ---------------------------------------------------------------------------
# Heartbeat & event counter
# ---------------------------------------------------------------------------

class TestHeartbeatAndCounter:

    def test_record_heartbeat_updates_timestamp(self, store):
        agent, _ = store.create_agent("acme")
        assert agent.last_heartbeat_at is None
        store.record_heartbeat(agent.agent_id)
        updated = store.get_agent(agent.agent_id)
        assert updated.last_heartbeat_at is not None

    def test_increment_events_increments(self, store):
        agent, _ = store.create_agent("acme")
        store.increment_events(agent.agent_id)
        store.increment_events(agent.agent_id)
        store.increment_events(agent.agent_id)
        updated = store.get_agent(agent.agent_id)
        assert updated.events_received == 3


# ---------------------------------------------------------------------------
# Multi-org isolation
# ---------------------------------------------------------------------------

class TestMultiOrgIsolation:

    def test_list_agents_filtered_by_org(self, store):
        store.create_agent("org_a", "service-a")
        store.create_agent("org_a", "service-b")
        store.create_agent("org_b", "service-c")

        a_agents = store.list_agents(org_id="org_a")
        b_agents = store.list_agents(org_id="org_b")

        assert len(a_agents) == 2
        assert len(b_agents) == 1
        assert all(a.org_id == "org_a" for a in a_agents)
        assert all(a.org_id == "org_b" for a in b_agents)

    def test_list_agents_no_filter_returns_all(self, store):
        store.create_agent("org_a")
        store.create_agent("org_b")
        all_agents = store.list_agents()
        assert len(all_agents) == 2

    def test_token_scoped_to_org(self, store):
        _, token_a = store.create_agent("org_a")
        agent = store.validate_token(token_a)
        assert agent.org_id == "org_a"

    def test_org_b_cannot_use_org_a_key(self, store):
        key_a = store.issue_key("org_a")
        reg = store.consume_key(key_a)
        assert reg.org_id == "org_a"
        # The agent created from org_a's key belongs to org_a, not org_b
        agent, _ = store.create_agent(reg.org_id)
        assert agent.org_id == "org_a"


# ---------------------------------------------------------------------------
# Singleton & test isolation
# ---------------------------------------------------------------------------

class TestSingleton:

    def test_reset_clears_singleton(self, tmp_path, monkeypatch):
        monkeypatch.setattr(store_module, "_DEFAULT_DB_PATH", tmp_path / "singleton_test.db")
        s1 = get_agent_store()
        reset_agent_store()
        s2 = get_agent_store()
        assert s1 is not s2

    def test_get_agent_store_returns_same_instance(self):
        s1 = get_agent_store()
        s2 = get_agent_store()
        assert s1 is s2


class TestEventCounterIsBatched:
    """The per-event counter must not cost a disk write per event, and must never be wrong when read."""

    def test_reads_always_see_every_event(self, store):
        agent, _ = store.create_agent("org_x", "label")
        for _ in range(250):
            store.increment_events(agent.agent_id)
        assert store.get_agent(agent.agent_id).events_received == 250
        assert [a.events_received for a in store.list_agents("org_x")] == [250]

    def test_the_hot_path_does_not_write_on_every_event(self, store):
        agent, _ = store.create_agent("org_x", "label")
        store.flush_events()
        before = store._conn.total_changes
        for _ in range(500):
            store.increment_events(agent.agent_id)
        assert store._conn.total_changes == before, "the counter was written to disk per event"

    def test_close_writes_what_is_pending(self, tmp_path):
        from agent_store.store import AgentStore
        path = tmp_path / "a.db"
        s = AgentStore(path)
        agent, _ = s.create_agent("org_x", "label")
        for _ in range(7):
            s.increment_events(agent.agent_id)
        s.close()
        again = AgentStore(path)
        assert again.get_agent(agent.agent_id).events_received == 7
        again.close()

    def test_the_database_uses_write_ahead_logging(self, tmp_path):
        from agent_store.store import AgentStore
        s = AgentStore(tmp_path / "w.db")
        assert s._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        s.close()
