"""The agent's database schema source (phase B): only whole DDL statements leave the host, tagged as schema events."""
import json
import queue
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import agent  # noqa: E402

J = agent.DdlJoiner


def feed_all(lines):
    j, out = J(), []
    for line in lines:
        out += j.feed(line)
    return out + j.flush_if_complete()


def test_a_single_line_statement_is_kept():
    assert feed_all(["2026-10-20 10:00:00 UTC LOG:  statement: ALTER TABLE users ADD COLUMN phone text;"]) == \
        ["2026-10-20 10:00:00 UTC LOG:  statement: ALTER TABLE users ADD COLUMN phone text;"]


def test_a_statement_over_several_lines_is_joined():
    out = feed_all(["2026-10-20 10:00:00 UTC LOG:  statement: CREATE TABLE applicants (", "\tid serial,", "\taadhaar_no varchar(12),", "\tdob date", ");"])
    assert len(out) == 1 and "aadhaar_no" in out[0] and "dob date" in out[0]


def test_a_statement_without_a_semicolon_ends_at_the_next_record():
    out = feed_all(["2026-10-20 10:00:00 LOG: statement: ALTER TABLE t ADD COLUMN a int", "\t, ADD COLUMN b int",
                    "2026-10-20 10:00:01 LOG: connection received", "2026-10-20 10:00:02 LOG: statement: ALTER TABLE u DROP COLUMN c"])
    assert len(out) == 1 or len(out) == 2
    assert "ADD COLUMN b" in out[0] and "connection received" not in out[0]


@pytest.mark.parametrize("line", [
    "2026-10-20 10:00:00 LOG:  statement: INSERT INTO users (phone) VALUES ('9876543210')",
    "2026-10-20 10:00:00 LOG:  statement: SELECT * FROM users WHERE phone = '9876543210'",
    "2026-10-20 10:00:00 LOG:  statement: UPDATE users SET aadhaar = '2345 6789 0124'",
    "2026-10-20 10:00:00 LOG:  connection authorized: user=app database=prod",
    "random text", "",
])
def test_nothing_that_might_carry_a_value_leaves(line):
    assert feed_all([line]) == []


def test_dropping_a_table_counts_as_ddl_and_a_huge_statement_is_cut():
    assert len(feed_all(["2026-10-20 10:00:00 LOG: statement: DROP TABLE old_customers;"])) == 1
    out = feed_all(["2026-10-20 10:00:00 LOG: statement: CREATE TABLE big ("] + ["\tcol%d int," % i for i in range(5000)] + ["2026-10-20 10:00:01 LOG: x"])
    assert out and all(len(s) < 40_000 for s in out)


def test_the_new_source_type_is_accepted_and_checked():
    ok = [{"type": "db_schema_log", "path": "/var/log/postgresql/postgresql.log", "source_system": "loan-db"}]
    assert agent.validate_sources(ok) == []
    assert any("needs a path" in p for p in agent.validate_sources([{"type": "db_schema_log", "source_system": "x"}]))
    assert any("needs a source_system" in p for p in agent.validate_sources([{"type": "db_schema_log", "path": "/x"}]))
    assert any("db_schema_log" in p for p in agent.validate_sources([{"type": "carrier-pigeon"}]))


class Capture(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):
        Capture.received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200); self.end_headers(); self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


def test_a_log_file_reaches_the_server_as_schema_events_only(tmp_path):
    Capture.received = []
    srv = HTTPServer(("127.0.0.1", 0), Capture)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        log = tmp_path / "db.log"
        log.write_text("2026-10-20 10:00:00 LOG:  statement: INSERT INTO t VALUES ('9876543210')\n"
                       "2026-10-20 10:00:01 LOG:  statement: ALTER TABLE customers ADD COLUMN aadhaar_no text;\n"
                       "2026-10-20 10:00:02 LOG:  connection authorized\n")
        q, stop = queue.Queue(), threading.Event()
        t = threading.Thread(target=agent.tail_file, args=(str(log), "loan-db", q),
                             kwargs={"kind": "schema", "joiner": J(), "src_type": "db_schema_log", "stop_event": stop,
                                     "poll_interval": 0.05}, daemon=True)
        # the follower starts at the end of an existing file: write the lines after it has started
        log.write_text("")
        t.start()
        time.sleep(0.4)
        with open(log, "a") as f:
            f.write("2026-10-20 10:00:00 LOG:  statement: INSERT INTO t VALUES ('9876543210')\n"
                    "2026-10-20 10:00:01 LOG:  statement: ALTER TABLE customers ADD COLUMN aadhaar_no text;\n"
                    "2026-10-20 10:00:02 LOG:  connection authorized\n")
        item = q.get(timeout=10)
        stop.set()
        assert q.empty() and item[2] == {"source_kind": "schema"} and "aadhaar_no" in item[0] and "9876543210" not in item[0]
        state = {"auth_token": "t", "event_endpoint": "/v1/o/events"}
        agent.deliver(item, lambda raw, system, meta=None: agent.forward_event(f"http://127.0.0.1:{srv.server_port}", state, raw, system, meta=meta),
                      stats=agent.AgentStats())
        assert Capture.received[0]["source_kind"] == "schema" and Capture.received[0]["source_system"] == "loan-db"
    finally:
        srv.shutdown()


def test_schema_lines_are_not_changed_by_redaction_but_keep_their_kind(monkeypatch):
    monkeypatch.setattr(agent, "REDACTOR", agent.Redactor({"mode": "mask"}))
    q = queue.Queue()
    agent._enqueue(q, "ALTER TABLE t ADD COLUMN phone text;", "db", "schema")
    line, system, meta = q.get_nowait()
    assert line == "ALTER TABLE t ADD COLUMN phone text;" and meta["source_kind"] == "schema" and meta["schema"] == 2
