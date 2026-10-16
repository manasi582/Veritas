"""
Tests for how the agent handles delivery failures.

The queue is processed in order, so one event that can never succeed must not
block every line behind it, while a server outage must not lose data.
"""
from __future__ import annotations

import json
import logging
import queue
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).parent))
import agent  # noqa: E402
from agent import AgentStats, deliver  # noqa: E402


class FakeResponse:
    def __init__(self, status, headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text


def http_error(status, headers=None, text=""):
    return requests.exceptions.HTTPError(f"{status}", response=FakeResponse(status, headers, text))


class Script:
    """A forward() that raises/returns a scripted sequence, and a sleep() that records delays."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0
        self.sleeps = []

    def forward(self, raw, system):
        self.calls += 1
        outcome = self.outcomes.pop(0) if self.outcomes else None
        if isinstance(outcome, BaseException):
            raise outcome

    def sleep(self, seconds):
        self.sleeps.append(seconds)


def run(script, item=("line", "order-service"), **kw):
    stats = AgentStats()
    result = deliver(item, script.forward, sleep=script.sleep, stats=stats, **kw)
    return result, stats.snapshot()


class TestOutagesAreRetriedWithoutLimit:
    def test_success(self):
        s = Script()
        result, stats = run(s)
        assert (result, s.calls, stats["forwarded"]) == ("delivered", 1, 1)

    def test_connection_errors_back_off_then_deliver(self):
        s = Script(requests.exceptions.ConnectionError("down"), requests.exceptions.ConnectionError("down"))
        result, stats = run(s)
        assert result == "delivered"
        assert s.sleeps == [1, 2]
        assert stats["retries"] == 2 and stats["forwarded"] == 1

    def test_backoff_is_capped(self):
        s = Script(*[requests.exceptions.ConnectionError("down")] * 8)
        result, _ = run(s, max_backoff=8)
        assert result == "delivered"
        assert s.sleeps == [1, 2, 4, 8, 8, 8, 8, 8]

    def test_timeouts_are_retried(self):
        s = Script(requests.exceptions.ReadTimeout("slow"))
        assert run(s)[0] == "delivered"

    @pytest.mark.parametrize("status", [408, 502, 503, 504])
    def test_gateway_style_errors_are_retried_many_times(self, status):
        s = Script(*[http_error(status)] * 20)
        result, stats = run(s)
        assert result == "delivered", "an outage behind a proxy must not drop data"
        assert stats["retries"] == 20 and stats["dropped_rejected"] == 0

    def test_503_busy_honours_retry_after(self):
        # the server's detection queue is full: it asks for a short wait, not a growing backoff
        s = Script(http_error(503, {"Retry-After": "1"}), http_error(503, {"Retry-After": "1"}))
        result, _ = run(s)
        assert result == "delivered" and s.sleeps == [1.0, 1.0]

    def test_429_honours_retry_after(self):
        s = Script(http_error(429, {"Retry-After": "7"}))
        result, _ = run(s)
        assert result == "delivered" and s.sleeps == [7.0]


class TestUnfixableEventsDoNotBlockTheQueue:
    @pytest.mark.parametrize("status", [400, 404, 413, 422])
    def test_client_errors_drop_immediately(self, status):
        s = Script(http_error(status, text="bad event"))
        result, stats = run(s)
        assert result == "dropped"
        assert s.calls == 1 and s.sleeps == []
        assert stats["dropped_rejected"] == 1

    @pytest.mark.parametrize("status", [401, 403])
    def test_auth_errors_drop_and_are_counted_separately(self, status):
        s = Script(http_error(status))
        result, stats = run(s)
        assert result == "dropped" and stats["dropped_auth"] == 1 and s.sleeps == []

    def test_persistent_500_is_dropped_after_bounded_attempts(self):
        s = Script(*[http_error(500)] * 50)
        result, stats = run(s)
        assert result == "dropped"
        assert s.calls == agent.MAX_SERVER_ERROR_ATTEMPTS
        assert stats["dropped_rejected"] == 1

    def test_transient_500_still_delivers(self):
        s = Script(http_error(500), http_error(500))
        result, stats = run(s)
        assert result == "delivered" and stats["retries"] == 2

    def test_tls_error_is_dropped_not_retried(self):
        s = Script(requests.exceptions.SSLError("bad cert"))
        result, stats = run(s)
        assert result == "dropped" and stats["dropped_other"] == 1 and s.sleeps == []

    def test_unexpected_exception_is_dropped(self):
        s = Script(ValueError("boom"))
        result, stats = run(s)
        assert result == "dropped" and stats["dropped_other"] == 1

    def test_poison_event_does_not_block_events_behind_it(self):
        def forward(raw, system):
            if raw == "POISON":
                raise http_error(422)

        stats = AgentStats()
        delivered = []
        for item in [("a", "x"), ("POISON", "x"), ("b", "x")]:
            if deliver(item, forward, sleep=lambda s: None, stats=stats) == "delivered":
                delivered.append(item[0])
        assert delivered == ["a", "b"]
        snap = stats.snapshot()
        assert snap["forwarded"] == 2 and snap["dropped_rejected"] == 1


class TestLogsDoNotLeakEventText:
    def test_rejected_event_text_is_not_logged(self, caplog):
        agent._last_logged.clear()
        s = Script(http_error(422, text="invalid"))
        with caplog.at_level(logging.DEBUG, logger="veritas.agent"):
            deliver(("customer phone 9876543210 aadhaar 2345 6789 0124", "order-service"),
                    s.forward, sleep=s.sleep, stats=AgentStats())
        assert "9876543210" not in caplog.text and "2345 6789" not in caplog.text
        assert "422" in caplog.text

    def test_repeated_warnings_are_rate_limited(self, caplog):
        agent._last_logged.clear()
        with caplog.at_level(logging.WARNING, logger="veritas.agent"):
            for _ in range(5):
                agent.log_limited("k", logging.WARNING, "same problem")
        assert caplog.text.count("same problem") == 1


class TestBoundedBuffer:
    def test_full_buffer_drops_oldest_and_keeps_newest(self):
        agent._last_logged.clear()
        before = agent.STATS.snapshot()
        q: queue.Queue = queue.Queue(maxsize=3)
        for i in range(5):
            agent._enqueue(q, f"line{i}", "svc")
        kept = [q.get_nowait()[0] for _ in range(q.qsize())]
        after = agent.STATS.snapshot()
        assert kept == ["line2", "line3", "line4"]
        assert after["lines_read"] - before["lines_read"] == 5
        assert after["dropped_buffer_full"] - before["dropped_buffer_full"] == 2


class _Handler(BaseHTTPRequestHandler):
    received = []
    fail_503_remaining = 0

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        text = body["raw_snippet"]
        if text == "POISON":
            status = 422
        elif _Handler.fail_503_remaining > 0:
            _Handler.fail_503_remaining -= 1
            status = 503
        else:
            status = 200
            _Handler.received.append(text)
        self.send_response(status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


def test_real_http_poison_event_and_short_outage():
    """End to end with the real forward_event against a local server."""
    _Handler.received = []
    _Handler.fail_503_remaining = 2
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        state = {"auth_token": "tok", "event_endpoint": "/v1/o/events"}
        base = f"http://127.0.0.1:{server.server_port}"

        def forward(raw, system):
            agent.forward_event(base, state, raw, system, verify=True)

        stats = AgentStats()
        results = [
            deliver((text, "svc"), forward, sleep=lambda s: None, stats=stats)
            for text in ["one", "POISON", "two"]
        ]
        assert results == ["delivered", "dropped", "delivered"]
        assert _Handler.received == ["one", "two"]
        snap = stats.snapshot()
        assert snap["retries"] == 2 and snap["dropped_rejected"] == 1 and snap["forwarded"] == 2
    finally:
        server.shutdown()
