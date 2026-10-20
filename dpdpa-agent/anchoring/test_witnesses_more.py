"""The e-mail, time-stamp authority and PDF digest witnesses (phase T7), against small stand-in servers."""
import base64
import hashlib
import json
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from anchoring import sinks
from anchoring.checkpoints import AnchorManager
from anchoring.config import AnchorConfig
from anchoring.sinks import (DigestSink, EmailSink, FileSink, TimestampSink, build_sinks, checkpoint_text, timestamp_request,
                             timestamp_response_status)
from evidence_store.store import EvidenceStore
from evidence_store.test_evidence_store import _make_explained_verdict

CP = {"type": "CHECKPOINT", "checkpoint_id": "cp1", "cp_seq": 7, "org": "org_a", "last_seq": 42, "head_hash": "ab" * 32,
      "record_count": 42, "created_at": "2026-10-20T10:00:00.000Z", "key_id": "k", "signature": "00"}


# ---- e-mail ---------------------------------------------------------------------------------------------------

class FakeSMTP(socketserver.StreamRequestHandler):
    mails: list = []

    def handle(self):
        w = lambda t: self.wfile.write((t + "\r\n").encode())
        w("220 fake ESMTP")
        data_mode, buf = False, []
        for raw in self.rfile:
            line = raw.decode(errors="replace").rstrip("\r\n")
            if data_mode:
                if line == ".":
                    FakeSMTP.mails.append("\n".join(buf)); data_mode = False; w("250 queued")
                else:
                    buf.append(line)
                continue
            cmd = line.split(" ")[0].upper()
            if cmd in ("EHLO", "HELO"):
                w("250 hello")
            elif cmd in ("MAIL", "RCPT", "NOOP"):
                w("250 ok")
            elif cmd == "DATA":
                data_mode, buf = True, []; w("354 go")
            elif cmd == "QUIT":
                w("221 bye"); return
            else:
                w("250 ok")


@pytest.fixture
def smtp():
    FakeSMTP.mails = []
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeSMTP)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_the_email_witness_mails_the_whole_checkpoint(smtp):
    sink = EmailSink(["audit@example.org"], "127.0.0.1", smtp, security="none", sender="veritas@example.org")
    receipt = sink.publish(CP)
    assert "not confirmed delivered" in receipt
    mail = FakeSMTP.mails[0]
    assert "Subject: Veritas checkpoint org_a #7" in mail and "audit@example.org" in mail
    assert checkpoint_text(CP) in mail.replace("=\n", "")
    assert sink.health()["ok"] is True


def test_the_email_witness_reports_an_unreachable_server():
    sink = EmailSink(["a@example.org"], "127.0.0.1", 1, security="none", timeout=2)
    assert sink.health()["ok"] is False
    with pytest.raises(OSError):
        sink.publish(CP)


@pytest.mark.parametrize("args", [([], "host"), (["a@b.c"], ""), (["a@b.c"], "h", 25, "tls-please")])
def test_an_incomplete_email_witness_is_refused(args):
    with pytest.raises(ValueError):
        EmailSink(*args)


# ---- time-stamp authority -------------------------------------------------------------------------------------

def parse_request(body: bytes):
    """Pull the digest and nonce back out of a TimeStampReq the way an authority would."""
    tag, s, e = sinks._read_der(body)
    assert tag == 0x30
    t, vs, ve = sinks._read_der(body, s)                      # version
    assert t == 0x02 and body[vs:ve] == b"\x01"
    t, ms, me = sinks._read_der(body, ve)                     # messageImprint
    t2, as_, ae = sinks._read_der(body, ms)                   # algorithm
    t3, ds, de = sinks._read_der(body, ae)                    # hashedMessage
    assert t3 == 0x04
    t4, ns, ne = sinks._read_der(body, me)                    # nonce
    return body[ds:de], body[ns:ne], body[ne:ne + 3]


def granted(digest: bytes, nonce: bytes, status: int = 0) -> bytes:
    token = sinks._der(0x30, sinks._der(0x04, digest) + sinks._der(0x02, nonce))
    return sinks._der(0x30, sinks._der(0x30, sinks._der_int(status)) + token)


class FakeTSA(BaseHTTPRequestHandler):
    mode = "ok"
    seen: list = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        digest, nonce, cert_req = parse_request(body)
        FakeTSA.seen.append((digest, nonce, cert_req, self.headers["Content-Type"]))
        resp = {"ok": granted(digest, nonce), "refused": granted(digest, nonce, 2), "other": granted(b"x" * 32, nonce),
                "junk": b"not der"}[FakeTSA.mode]
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.end_headers()
        self.wfile.write(resp)

    def do_HEAD(self):
        self.send_response(200); self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def tsa():
    FakeTSA.mode, FakeTSA.seen = "ok", []
    srv = HTTPServer(("127.0.0.1", 0), FakeTSA)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/tsr"
    srv.shutdown()


def test_the_authority_receives_the_sha256_of_the_checkpoint_and_the_token_is_kept(tsa):
    receipt = TimestampSink(tsa).publish(CP)
    digest, nonce, cert_req, ctype = FakeTSA.seen[0]
    assert digest == hashlib.sha256(checkpoint_text(CP).encode()).digest() and len(nonce) >= 1
    assert cert_req == b"\x01\x01\xff" and ctype == "application/timestamp-query"
    token = base64.b64decode(receipt.removeprefix("tsr:"))
    assert timestamp_response_status(token) == 0 and digest in token


@pytest.mark.parametrize("mode,fragment", [("refused", "refused"), ("other", "does not match"), ("junk", "")])
def test_a_refused_or_mismatched_response_is_a_failure(tsa, mode, fragment):
    FakeTSA.mode = mode
    with pytest.raises(Exception) as e:
        TimestampSink(tsa).publish(CP)
    assert fragment in str(e.value)


def test_the_request_is_well_formed_der():
    req = timestamp_request(b"d" * 32, 2 ** 63 + 5)
    digest, nonce, cert = parse_request(req)
    assert digest == b"d" * 32 and int.from_bytes(nonce, "big") == 2 ** 63 + 5 and cert == b"\x01\x01\xff"


def test_the_authority_health_check_and_bad_addresses(tsa):
    assert TimestampSink(tsa).health()["ok"] is True
    assert TimestampSink("http://127.0.0.1:1/x", timeout=2).health()["ok"] is False
    with pytest.raises(ValueError):
        TimestampSink("ftp://example.org")


# ---- PDF digest -----------------------------------------------------------------------------------------------

def test_the_digest_is_a_daily_pdf_that_grows_with_each_checkpoint(tmp_path):
    sink = DigestSink(str(tmp_path))
    r1 = sink.publish(CP)
    r2 = sink.publish({**CP, "cp_seq": 8, "checkpoint_id": "cp2", "head_hash": "cd" * 32})
    pdf = (tmp_path / "org_a" / "checkpoints-20261020.pdf").read_bytes()
    assert pdf.startswith(b"%PDF") and b"#7" in pdf and b"#8" in pdf and ("cd" * 32).encode() in pdf
    assert r1 != r2 and "sha256=" in r2
    lines = (tmp_path / "org_a" / "checkpoints-20261020.jsonl").read_text().splitlines()
    assert [json.loads(x)["cp_seq"] for x in lines] == [7, 8]
    assert sink.health()["ok"] is True


# ---- configuration and the manager ------------------------------------------------------------------------------

def test_the_new_witnesses_can_be_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_SMTP_HOST", "mail.example.org")
    built = build_sinks([{"type": "email", "to": "a@example.org, b@example.org"}, {"type": "tsa", "url": "https://tsa.example.org/ts"},
                         {"type": "pdf-digest", "path": str(tmp_path)}, {"type": "file", "path": str(tmp_path / "f")}])
    assert [type(s).__name__ for s in built] == ["EmailSink", "TimestampSink", "DigestSink", "FileSink"]
    assert built[0].to == ["a@example.org", "b@example.org"] and built[0].host == "mail.example.org"
    with pytest.raises(ValueError, match="email, tsa or pdf-digest"):
        build_sinks([{"type": "carrier-pigeon"}])


def test_a_checkpoint_is_witnessed_by_a_file_a_digest_and_an_authority(tmp_path, tsa, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "data"))
    store = EvidenceStore(tmp_path / "e.db")
    try:
        for _ in range(3):
            store.append(_make_explained_verdict(tenant_id="org_a"))
        mgr = AnchorManager(store, AnchorConfig(enabled=True, min_witnesses=3),
                            sinks=[FileSink(str(tmp_path / "w1")), DigestSink(str(tmp_path / "w2")), TimestampSink(tsa)])
        cp = mgr.checkpoint_now("org_a")
        mgr.publish_pending("org_a")
        listed = mgr.list_checkpoints("org_a")[0]
        assert cp and listed["status"] == "WITNESSED" and len(listed["receipts"]) == 3
        assert any(str(r.get("receipt", "")).startswith("tsr:") for r in listed["receipts"])
    finally:
        store.close()
