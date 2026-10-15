"""A program must not run on data written by a newer release."""
import sqlite3

import pytest

import schema_guard as sg


def _db(path, version=0):
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE t (x)")
    c.execute("INSERT INTO t VALUES (1)")
    c.execute(f"PRAGMA user_version = {version}")
    c.commit(); c.close()


def test_missing_files_are_fine(tmp_path):
    assert sg.check_and_stamp(tmp_path) == {}


def test_older_databases_are_stamped(tmp_path):
    _db(tmp_path / "evidence.db", 0)
    _db(tmp_path / "users.db", 0)
    before = sg.check_and_stamp(tmp_path, generation=3)
    assert before == {"evidence.db": 0, "users.db": 0}
    assert sg.read_generation(tmp_path / "evidence.db") == 3
    assert sg.read_generation(tmp_path / "users.db") == 3


def test_stamping_keeps_the_data(tmp_path):
    _db(tmp_path / "audit.db", 0)
    sg.check_and_stamp(tmp_path)
    c = sqlite3.connect(tmp_path / "audit.db")
    assert c.execute("SELECT x FROM t").fetchall() == [(1,)]
    c.close()


def test_a_newer_database_is_refused_with_the_reason(tmp_path):
    _db(tmp_path / "users.db", 7)
    with pytest.raises(sg.SchemaTooNew) as e:
        sg.check_and_stamp(tmp_path, generation=2)
    assert "users.db" in str(e.value) and "newer version" in str(e.value)


def test_a_refusal_leaves_every_file_untouched(tmp_path):
    _db(tmp_path / "evidence.db", 0)
    _db(tmp_path / "users.db", 9)
    with pytest.raises(sg.SchemaTooNew):
        sg.check_and_stamp(tmp_path, generation=2)
    assert sg.read_generation(tmp_path / "evidence.db") == 0


def test_same_generation_is_a_no_op(tmp_path):
    _db(tmp_path / "agents.db", 2)
    assert sg.check_and_stamp(tmp_path, generation=2) == {"agents.db": 2}


def test_an_unreadable_file_is_left_to_the_store_to_report(tmp_path):
    (tmp_path / "evidence.db").write_bytes(b"this is not a database" * 50)
    assert sg.check_and_stamp(tmp_path) == {}


def test_stores_still_open_a_stamped_database(tmp_path, monkeypatch):
    """The generation stamp must not upset the stores that create their own tables."""
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path))
    from user_store.store import UserStore
    store = UserStore(str(tmp_path / "users.db"))
    store.close() if hasattr(store, "close") else None
    sg.check_and_stamp(tmp_path)
    UserStore(str(tmp_path / "users.db"))
