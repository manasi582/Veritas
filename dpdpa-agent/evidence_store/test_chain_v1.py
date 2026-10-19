"""
The foundation: version 1 records, events in the chain, mixed chains, tampering, and migration of a real old database.
"""
import hashlib
import json
import shutil
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from db_encryption import decrypt_field, encrypt_field
from evidence_store import canonical as cn
from evidence_store.store import GENESIS_HASH, EvidenceStore
from evidence_store.test_evidence_store import _make_explained_verdict

ORG = "chain_org"
LEGACY_DB = Path(__file__).resolve().parent / "evidence.db"      # a real database from before this change (4,233 rows)


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "e.db")
    yield s
    s.close()


def _fill(store, n=3):
    ids = []
    for _ in range(n):
        ev = _make_explained_verdict(tenant_id=ORG)
        store.append(ev)
        ids.append(str(ev.verdict.verdict_id))
    return ids


def _rows(store):
    return store._conn.execute("SELECT * FROM evidence WHERE tenant_id = ? ORDER BY row_index", (ORG,)).fetchall()


# ---- new records ------------------------------------------------------------------------------

def test_new_records_are_version_1_with_a_gapless_sequence(store):
    _fill(store, 4)
    rows = _rows(store)
    assert [r["hash_version"] for r in rows] == [1] * 4
    assert [r["seq"] for r in rows] == [1, 2, 3, 4]
    assert rows[0]["previous_hash"] == GENESIS_HASH and rows[1]["previous_hash"] == rows[0]["row_hash"]
    assert store.verify_chain(ORG)["valid"] is True


def test_a_stored_record_is_the_canonical_body_and_its_hash_follows_the_published_definition(store):
    _fill(store, 2)
    rows = _rows(store)
    body_text = decrypt_field(rows[1]["payload_json"])
    body = json.loads(body_text)
    assert body_text == cn.canonical_json(body)
    material = "veritas-chain-v1\n" + rows[1]["previous_hash"] + "\n" + body_text
    assert hashlib.sha256(material.encode("utf-8")).hexdigest() == rows[1]["row_hash"]
    assert body["type"] == "VERDICT" and body["org"] == ORG and body["seq"] == 2


def test_readers_still_see_the_old_field_names(store):
    ev = _make_explained_verdict(tenant_id=ORG)
    store.append(ev)
    row = store.query(ORG)[0]
    assert row["tenant_id"] == ORG and row["breach_notification_candidate"] is True
    assert row["confidence"] == pytest.approx(0.9) and row["used_fallback"] is False
    assert row["rule_id"] == ev.verdict.rule_id.value
    assert store.get_by_verdict_id(ORG, str(ev.verdict.verdict_id))["confidence"] == pytest.approx(0.9)


# ---- events -----------------------------------------------------------------------------------

def test_a_status_change_is_a_chained_event_and_the_cache_agrees(store):
    vid = _fill(store, 1)[0]
    store.update_status(ORG, vid, "ACKNOWLEDGED", actor="asha", reason="owner informed")
    rows = _rows(store)
    assert [r["record_type"] for r in rows] == ["VERDICT", "STATUS_CHANGE"]
    event = json.loads(decrypt_field(rows[1]["payload_json"]))
    assert (event["target"], event["old_status"], event["new_status"], event["actor"], event["reason"]) == \
        (vid, "OPEN", "ACKNOWLEDGED", "asha", "owner informed")
    assert rows[0]["remediation_status"] == "ACKNOWLEDGED"
    assert store.verify_chain(ORG)["valid"] is True


def test_events_are_not_counted_as_findings(store):
    vid = _fill(store, 2)[0]
    store.update_status(ORG, vid, "ACKNOWLEDGED")
    store.add_comment(ORG, vid, "looked at it", author_name="asha")
    assert store.count(ORG) == 2 and len(store.query(ORG)) == 2
    assert store.stats(ORG)["total"] == 2 and store.stats(ORG)["by_status"] == {"ACKNOWLEDGED": 1, "OPEN": 1}


def test_a_comment_is_chained_by_its_hash_and_the_text_stays_beside_it(store):
    vid = _fill(store, 1)[0]
    store.add_comment(ORG, vid, "Owner informed; fix scheduled.", author_name="asha")
    event = json.loads(decrypt_field(_rows(store)[1]["payload_json"]))
    assert event["type"] == "COMMENT" and event["text_sha256"] == hashlib.sha256(b"Owner informed; fix scheduled.").hexdigest()
    assert "text" not in event and store.get_comments(ORG, vid)[0]["content"] == "Owner informed; fix scheduled."
    assert store.verify_chain(ORG)["valid"] is True


def test_the_cached_status_cannot_be_changed_quietly(store):
    vid = _fill(store, 1)[0]
    store._conn.execute("UPDATE evidence SET remediation_status = 'RESOLVED' WHERE verdict_id = ?", (vid,))
    store._conn.commit()
    d = store.verify_chain_detail(ORG)
    assert d["valid"] is False and d["reason"] == "STATUS_CACHE_MISMATCH" and d["first_broken_index"] == 0


def test_an_edited_event_is_caught(store):
    vid = _fill(store, 1)[0]
    store.update_status(ORG, vid, "ACKNOWLEDGED", actor="asha")
    row = _rows(store)[1]
    forged = json.loads(decrypt_field(row["payload_json"]))
    forged["actor"] = "someone_else"
    store._conn.execute("UPDATE evidence SET payload_json = ? WHERE row_index = ?",
                        (encrypt_field(cn.canonical_json(forged)), row["row_index"]))
    store._conn.commit()
    d = store.verify_chain_detail(ORG)
    assert d["valid"] is False and d["reason"] == "HASH_MISMATCH" and d["first_broken_index"] == 1


def test_a_removed_event_leaves_a_status_the_chain_cannot_explain(store):
    vid = _fill(store, 1)[0]
    store.update_status(ORG, vid, "ACKNOWLEDGED")
    store._conn.execute("DELETE FROM evidence WHERE record_type = 'STATUS_CHANGE'")
    store._conn.commit()
    assert store.verify_chain_detail(ORG)["reason"] == "STATUS_CACHE_MISMATCH"


def test_status_rules_still_hold(store):
    vid = _fill(store, 1)[0]
    with pytest.raises(ValueError):
        store.update_status(ORG, vid, "RESOLVED")                 # cannot skip a step
    with pytest.raises(ValueError):
        store.update_status("another_org", vid, "ACKNOWLEDGED")   # another tenant's id is "not found"
    assert [r["record_type"] for r in _rows(store)] == ["VERDICT"]    # a refused change leaves no event


# ---- tampering with the records themselves ----------------------------------------------------

def test_every_kind_of_tampering_names_a_reason(store):
    ids = _fill(store, 4)
    rows = _rows(store)
    # 1. edit a record, keep its stored hash
    body = json.loads(decrypt_field(rows[1]["payload_json"])); body["severity"] = "LOW"
    store._conn.execute("UPDATE evidence SET payload_json = ? WHERE row_index = ?",
                        (encrypt_field(cn.canonical_json(body)), rows[1]["row_index"])); store._conn.commit()
    assert store.verify_chain_detail(ORG)["reason"] == "HASH_MISMATCH"
    store._conn.execute("UPDATE evidence SET payload_json = ? WHERE row_index = ?",
                        (rows[1]["payload_json"], rows[1]["row_index"])); store._conn.commit()
    assert store.verify_chain(ORG)["valid"] is True
    # 2. delete a record in the middle
    store._conn.execute("DELETE FROM evidence WHERE row_index = ?", (rows[2]["row_index"],)); store._conn.commit()
    d = store.verify_chain_detail(ORG)
    assert d["valid"] is False and d["reason"] in ("CHAIN_BREAK", "HASH_MISMATCH") and d["first_broken_index"] == 2


def test_a_changed_summary_column_is_caught_for_the_new_format_too(store):
    _fill(store, 2)
    store._conn.execute("UPDATE evidence SET source_system = 'elsewhere' WHERE seq = 1"); store._conn.commit()
    assert store.verify_chain_detail(ORG)["reason"] == "SUMMARY_MISMATCH"


# ---- an old database ---------------------------------------------------------------------------

def _legacy_verify(db, tenant):
    """The original algorithm, written out independently of the store."""
    c = sqlite3.connect(db); c.row_factory = sqlite3.Row
    rows = c.execute("SELECT payload_json,row_hash,previous_hash FROM evidence WHERE tenant_id=? ORDER BY row_index",
                     (tenant,)).fetchall()
    prev = GENESIS_HASH
    for i, r in enumerate(rows):
        if hashlib.sha256((r["payload_json"] + prev).encode()).hexdigest() != r["row_hash"] or r["previous_hash"] != prev:
            return {"valid": False, "first_broken_index": i}
        prev = r["row_hash"]
    c.close()
    return {"valid": True, "first_broken_index": None}


@pytest.mark.skipif(not LEGACY_DB.exists(), reason="the old development database is not in this checkout")
def test_a_real_old_database_migrates_without_changing_any_verdict_about_it(tmp_path):
    db = tmp_path / "old.db"
    shutil.copy(LEGACY_DB, db)
    tenants = [r[0] for r in sqlite3.connect(db).execute("SELECT DISTINCT tenant_id FROM evidence")]
    before = {t: _legacy_verify(db, t) for t in tenants}
    old_hashes = {r[0]: r[1] for r in sqlite3.connect(db).execute("SELECT row_index,row_hash FROM evidence")}

    s = EvidenceStore(db)                                   # migrates
    try:
        assert {t: s.verify_chain(t) for t in tenants} == before          # same answer as before the migration
        conn = s._conn
        assert {r[0]: r[1] for r in conn.execute("SELECT row_index,row_hash FROM evidence")} == old_hashes
        assert conn.execute("SELECT COUNT(*) FROM evidence WHERE hash_version = 0").fetchone()[0] == len(old_hashes)
        assert list((tmp_path / "backups").glob("evidence-before-migration-*.db")), "no copy was made before migrating"
        # new records continue the old chain of a tenant that verified, and everything still verifies
        good = [t for t in tenants if before[t]["valid"] and t]
        assert good, "expected at least one organization with a sound old chain"
        t = good[0]
        last = conn.execute("SELECT row_hash FROM evidence WHERE tenant_id=? ORDER BY row_index DESC LIMIT 1", (t,)).fetchone()[0]
        n_before = s.count(t)
        s.append(_make_explained_verdict(tenant_id=t))
        newest = conn.execute("SELECT previous_hash,hash_version FROM evidence WHERE tenant_id=? ORDER BY row_index DESC LIMIT 1", (t,)).fetchone()
        assert newest[0] == last and newest[1] == 1
        assert s.count(t) == n_before + 1 and s.verify_chain(t)["valid"] is True
        old = s.query(t)[0]
        s.update_status(t, old["verdict_id"], "ACKNOWLEDGED", actor="test") if old["remediation_status"] == "OPEN" else None
        assert s.verify_chain(t)["valid"] is True
    finally:
        s.close()
    # opening it again is a no-op
    s2 = EvidenceStore(db)
    assert s2.verify_chain(t)["valid"] is True
    s2.close()


def test_a_tampered_old_record_is_still_caught_after_migration(tmp_path):
    db = tmp_path / "small.db"
    c = sqlite3.connect(db)
    c.executescript("""CREATE TABLE evidence (row_index INTEGER PRIMARY KEY AUTOINCREMENT, verdict_id TEXT NOT NULL UNIQUE,
        payload_json TEXT NOT NULL, row_hash TEXT NOT NULL, previous_hash TEXT NOT NULL,
        remediation_status TEXT NOT NULL DEFAULT 'OPEN', remediation_updated_at TEXT, appended_at TEXT NOT NULL,
        tenant_id TEXT, violation_id INTEGER);""")
    prev = GENESIS_HASH
    for n in range(1, 4):
        payload = json.dumps({"verdict_id": str(uuid.uuid4()), "tenant_id": "old_org", "rule_id": "EXPOSURE_001",
                              "severity": "HIGH", "source_system": "s", "breach_notification_candidate": False}, sort_keys=True)
        h = hashlib.sha256((payload + prev).encode()).hexdigest()
        c.execute("INSERT INTO evidence (verdict_id,payload_json,row_hash,previous_hash,appended_at,tenant_id,violation_id) VALUES (?,?,?,?,?,?,?)",
                  (json.loads(payload)["verdict_id"], payload, h, prev, datetime.now(timezone.utc).isoformat(), "old_org", n))
        prev = h
    c.commit(); c.close()
    s = EvidenceStore(db)
    assert s.verify_chain("old_org")["valid"] is True
    s._conn.execute("UPDATE evidence SET payload_json = replace(payload_json, 'HIGH', 'LOW') WHERE seq = 2"); s._conn.commit()
    d = s.verify_chain_detail("old_org")
    assert d["valid"] is False and d["first_broken_index"] == 1
    s.close()
