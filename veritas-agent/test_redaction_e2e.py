"""
A log file with personal data goes through the real reading, redacting, queueing and sending code to a stand-in
server. What the server receives, and what the masked copy holds, must contain no raw value.
"""
from __future__ import annotations

import json
import queue
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import agent  # noqa: E402

PHONE, AADHAAR, CARD, EMAIL = "9876543210", "2345 6789 0124", "4111 1111 1111 1111", "asha.rao@example.com"
LINES = [
    f"2026-10-20 10:00:01 INFO order 1 paid by {CARD}",
    f"2026-10-20 10:00:02 WARN callback to {PHONE} failed, mail {EMAIL}",
    f"2026-10-20 10:00:03 DEBUG kyc uid {AADHAAR} verified",
    "2026-10-20 10:00:04 INFO nothing personal here",
]


class Capture(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        Capture.received.append(json.loads(body))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    Capture.received = []
    srv = HTTPServer(("127.0.0.1", 0), Capture)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setattr(agent, "STATS", agent.AgentStats())
    monkeypatch.setattr(agent, "REDACTOR", agent.Redactor())
    monkeypatch.setattr(agent, "REDACTION_COUNTS", agent.RedactionCounts())
    monkeypatch.setattr(agent, "REDACTION_DROPS", agent.RedactionCounts())


def run_pipeline(tmp_path, base_url, section):
    log = tmp_path / "app.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    tee = agent.MaskedTee(str(tmp_path / "masked.log")) if section.get("tee_file") else None
    section = {**section, "tee_file": str(tmp_path / "masked.log")} if tee else section
    agent.REDACTOR = agent.Redactor(section, tee)
    q = queue.Queue()
    follower = agent.FileFollower(log, read_from_start=True)
    for line in follower.poll():
        agent._enqueue(q, line, "order-service")
    state = {"auth_token": "t", "event_endpoint": "/v1/o/events"}
    forward = lambda raw, system, meta=None: agent.forward_event(base_url, state, raw, system, meta=meta)
    while not q.empty():
        agent.deliver(q.get_nowait(), forward)
    return log


def test_masking_a_file_end_to_end(tmp_path, server):
    log = run_pipeline(tmp_path, server, {"mode": "mask", "tee_file": "yes"})
    sent = json.dumps(Capture.received)
    for raw in (PHONE, AADHAAR, CARD, EMAIL, "2345", "4111"):
        assert raw not in sent
    assert len(Capture.received) == 4
    assert all(e["schema"] == 2 and e["redaction_mode"] == "mask" for e in Capture.received)
    assert [e["agent_detections"] for e in Capture.received] == [{"card": 1}, {"phone": 1, "email": 1}, {"aadhaar": 1}, {}]
    masked = (tmp_path / "masked.log").read_text(encoding="utf-8")
    assert all(raw not in masked for raw in (PHONE, AADHAAR, CARD, EMAIL))
    assert masked.count("\n") == 4 and "nothing personal here" in masked
    assert PHONE in log.read_text(encoding="utf-8")                 # the application's own file is not touched


def test_dropping_a_kind_sends_no_line_for_it(tmp_path, server):
    run_pipeline(tmp_path, server, {"mode": "mask", "categories": {"card": "drop"}})
    texts = [e["raw_snippet"] for e in Capture.received]
    assert len(texts) == 3 and not any("order 1" in t for t in texts)
    assert agent.REDACTION_DROPS.snapshot() == {"card": 1}


def test_hashing_sends_tokens_the_server_can_match(tmp_path, server):
    run_pipeline(tmp_path, server, {"mode": "hash", "hash_key": "k" * 32})
    sent = json.dumps(Capture.received)
    assert PHONE not in sent and "[PHONE#" in sent and "[CARD#" in sent


def test_a_failure_to_redact_sends_nothing_when_fail_closed(tmp_path, server, monkeypatch):
    monkeypatch.setattr(agent.vr, "scan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    run_pipeline(tmp_path, server, {"mode": "mask"})
    assert Capture.received == [] and agent.STATS.snapshot()["dropped_redaction_error"] == 4


def test_without_redaction_the_events_are_schema_1(tmp_path, server):
    run_pipeline(tmp_path, server, {})
    assert len(Capture.received) == 4 and all("schema" not in e for e in Capture.received)
    assert PHONE in json.dumps(Capture.received)
