"""The agent's syslog source (phase F): UDP and TCP on loopback, framing, limits, and configuration checks."""
import queue
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import agent  # noqa: E402


def free_port(kind=socket.SOCK_DGRAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(protocol, **kw):
    port = free_port(socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM)
    q, stop, ready = queue.Queue(), threading.Event(), threading.Event()
    t = threading.Thread(target=agent.serve_syslog, args=("127.0.0.1", port, protocol, "edge-gateway", q),
                         kwargs={"stop_event": stop, "ready": ready, **kw}, daemon=True)
    t.start()
    assert ready.wait(5)
    return port, q, stop


def get(q, n=1, timeout=5):
    return [q.get(timeout=timeout) for _ in range(n)]


def test_udp_messages_become_log_lines_for_the_named_system():
    port, q, stop = start("udp")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"<34>1 2026-10-20T10:00:00Z gw app - - - login failed for 9876543210\n", ("127.0.0.1", port))
            s.sendto(b"<13>Oct 20 10:00:01 gw app: second message\r\n", ("127.0.0.1", port))
        items = get(q, 2)
        assert [i[1] for i in items] == ["edge-gateway"] * 2
        assert "login failed for 9876543210" in items[0][0] and items[1][0].endswith("second message")
    finally:
        stop.set()


def test_one_datagram_with_several_lines_gives_several_messages():
    port, q, stop = start("udp")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"one\ntwo\n\nthree", ("127.0.0.1", port))
        assert [i[0] for i in get(q, 3)] == ["one", "two", "three"]
    finally:
        stop.set()


def test_tcp_accepts_newline_separated_and_octet_counted_frames():
    port, q, stop = start("tcp")
    try:
        with socket.create_connection(("127.0.0.1", port)) as s:
            s.sendall(b"plain line one\nplain line two\n")
            msg = b"<14>1 2026-10-20T10:00:00Z h a - - - counted frame with spaces and \nnewline"
            s.sendall(str(len(msg)).encode() + b" " + msg)
            s.sendall(b"last line\n")
        got = [i[0] for i in get(q, 4)]
        assert got[:2] == ["plain line one", "plain line two"] and "counted frame with spaces and \nnewline" in got[2] and got[3] == "last line"
    finally:
        stop.set()


def test_a_line_arriving_in_pieces_is_put_together():
    port, q, stop = start("tcp")
    try:
        with socket.create_connection(("127.0.0.1", port)) as s:
            s.sendall(b"half a li")
            time.sleep(0.2)
            s.sendall(b"ne\n")
        assert get(q)[0][0] == "half a line"
    finally:
        stop.set()


def test_a_long_message_is_cut_and_binary_junk_does_not_break_the_listener():
    port, q, stop = start("udp", max_message=100)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"x" * 5000, ("127.0.0.1", port))
            s.sendto(b"\xff\xfe\x00\x01 binary", ("127.0.0.1", port))
            s.sendto(b"still alive", ("127.0.0.1", port))
        items = [i[0] for i in get(q, 3)]
        assert len(items[0]) == 100 and items[2] == "still alive"
    finally:
        stop.set()


def test_syslog_lines_are_redacted_like_any_other_when_redaction_is_on(monkeypatch):
    monkeypatch.setattr(agent, "REDACTOR", agent.Redactor({"mode": "mask"}))
    port, q, stop = start("udp")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"callback to 9876543210", ("127.0.0.1", port))
        line, system, meta = get(q)[0]
        assert line == "callback to [PHONE_REDACTED]" and meta["agent_detections"] == {"phone": 1}
    finally:
        stop.set()


@pytest.mark.parametrize("source,fragment", [
    ({"type": "syslog", "source_system": "x"}, "port"),
    ({"type": "syslog", "source_system": "x", "port": 0}, "port"),
    ({"type": "syslog", "source_system": "x", "port": 70000}, "port"),
    ({"type": "syslog", "source_system": "x", "port": "514"}, "port"),
    ({"type": "syslog", "port": 514}, "source_system"),
    ({"type": "syslog", "source_system": "x", "port": 514, "protocol": "sctp"}, "protocol"),
])
def test_bad_syslog_sources_are_explained(source, fragment):
    assert any(fragment in p for p in agent.validate_sources([source]))


def test_good_syslog_sources_pass():
    assert agent.validate_sources([{"type": "syslog", "source_system": "gw", "port": 5140},
                                   {"type": "syslog", "source_system": "gw", "port": 5141, "protocol": "TCP", "host": "0.0.0.0"}]) == []
