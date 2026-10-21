"""The Python payload tap (phase C): what it finds, that it masks first, that it never harms the application."""
import asyncio
import io
import json
import queue
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import veritas_recognizers as vr  # noqa: E402
import veritas_tap as vt  # noqa: E402

PHONE, AADHAAR, EMAIL, CARD = "9876543210", "2345 6789 0124", "asha.rao@example.com", "4111 1111 1111 1111"
RAW = (PHONE, AADHAAR, "234567890124", EMAIL, "asha.rao", CARD)


def make_tap(**kw):
    kw.setdefault("start", False)
    return vt.Tap("http://127.0.0.1:1", "token", "org_a", "customer-api", **kw)


def drain(tap):
    out = []
    while True:
        try:
            out.append(tap.q.get_nowait())
        except queue.Empty:
            return out


# ---- finding and masking ------------------------------------------------------------------------------------

def test_a_nested_body_gives_masked_fields_with_paths_and_counts():
    body = {"user": {"phone": PHONE, "email": EMAIL, "nickname": "asha"}, "items": [{"mobile": PHONE}, {"mobile": PHONE}], "total": 120}
    fields, counts = vt.inspect_body(body)
    assert fields == {"user.phone": "[PHONE_REDACTED]", "user.email": "[EMAIL_REDACTED]", "items[].mobile": "[PHONE_REDACTED]"}
    assert counts == {"phone": 3, "email": 1}


def test_a_value_inside_a_longer_text_is_masked_in_place():
    fields, _ = vt.inspect_body({"note": f"call {PHONE} or mail {EMAIL} about 12345"})
    assert fields == {"note": "call [PHONE_REDACTED] or mail [EMAIL_REDACTED] about 12345"}


def test_numbers_and_booleans_are_looked_at_and_nothing_else_is_reported():
    fields, counts = vt.inspect_body({"phone": 9876543210, "ok": True, "n": 5, "nothing": None})
    assert fields == {"phone": "[PHONE_REDACTED]"} and counts == {"phone": 1}


def test_hash_mode_gives_keyed_tokens_not_placeholders():
    key = b"k" * 32
    fields, _ = vt.inspect_body({"user": {"phone": "+91 " + PHONE}}, mode="hash", key=key)
    assert fields == {"user.phone": "+" + vr.hash_token("PHONE", PHONE, key)} or vr.key_id_of(key) in fields["user.phone"]
    assert PHONE not in json.dumps(fields)


def test_limits_hold_depth_breadth_and_field_count():
    deep = cur = {}
    for _ in range(50):
        cur["a"] = {}
        cur = cur["a"]
    cur["phone"] = PHONE
    assert vt.inspect_body(deep)[0] == {}                                              # too deep to be reported
    wide = {f"f{i}": PHONE for i in range(500)}
    fields, counts = vt.inspect_body(wide, max_fields=50)
    assert len(fields) == 50 and counts["phone"] == 500
    assert vt.inspect_body([[PHONE]] * 10)[0] == {"[][]": "[PHONE_REDACTED]"}


@pytest.mark.parametrize("body", ["", "null", "[]", "{}", '"text"', "12", '{"a": ' + "[" * 3000 + "}"])
def test_odd_bodies_are_survived(body):
    tap = make_tap()
    tap.observe("POST", "/x", 200, "response", body.encode())
    assert drain(tap) == []


def test_route_templates():
    assert vt.route_template("/customers/123/orders/9f1c2b3a-1111-2222-3333-444455556666") == "/customers/{id}/orders/{id}"
    assert vt.route_template("/customers/123", "/customers/{customer_id}") == "/customers/{customer_id}"
    assert vt.route_template("/health") == "/health"


# ---- what is reported ----------------------------------------------------------------------------------------

def test_an_event_carries_placeholders_paths_and_counts_but_no_value():
    tap = make_tap()
    tap.observe("GET", "/customers/42", 200, "response", json.dumps({"user": {"phone": PHONE, "aadhaar": AADHAAR}}).encode())
    (event,) = drain(tap)
    assert event["source_type"] == "api" and event["source_kind"] == "api" and event["source_system"] == "customer-api"
    assert event["fields"] == {"user.phone": "[PHONE_REDACTED]", "user.aadhaar": "[AADHAAR_REDACTED]"}
    assert event["agent_detections"] == {"phone": 1, "aadhaar": 1} and event["schema"] == 2 and event["redaction_mode"] == "mask"
    assert event["raw_snippet"] == "GET /customers/{id} 200 response carrying personal data in 2 field(s)"
    assert not any(raw in json.dumps(event) for raw in RAW)


def test_a_body_without_personal_data_reports_nothing():
    tap = make_tap()
    tap.observe("GET", "/ping", 200, "response", b'{"status": "ok", "order": 77}')
    assert drain(tap) == []


def test_the_same_route_and_fields_are_reported_at_most_once_per_interval():
    tap = make_tap(min_interval_seconds=60)
    for _ in range(50):
        tap.observe("GET", "/customers/1", 200, "response", json.dumps({"phone": PHONE}).encode())
    assert len(drain(tap)) == 1 and tap.stats["skipped_interval"] == 49
    tap.observe("GET", "/customers/1", 200, "response", json.dumps({"phone": PHONE, "email": EMAIL}).encode())   # new fields: reported
    tap.observe("GET", "/customers/1", 500, "response", json.dumps({"phone": PHONE}).encode())                   # new status: reported
    assert len(drain(tap)) == 2


def test_sampling_and_the_size_limit():
    tap = make_tap(sample_every=4, min_interval_seconds=0)
    for _ in range(8):
        tap.observe("GET", "/a", 200, "response", json.dumps({"phone": PHONE}).encode())
    assert len(drain(tap)) == 2
    big = make_tap(max_body_bytes=100)
    big.observe("GET", "/a", 200, "response", json.dumps({"phone": PHONE, "pad": "x" * 500}).encode())
    assert drain(big) == []


# ---- masking comes first and failures drop the sample --------------------------------------------------------------

def test_if_masking_fails_the_sample_is_dropped_not_sent(monkeypatch):
    tap = make_tap()
    monkeypatch.setattr(vr, "scan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    tap.observe("GET", "/a", 200, "response", json.dumps({"phone": PHONE}).encode())
    assert drain(tap) == [] and tap.stats["masking_errors"] == 1


def test_nothing_raw_is_ever_handed_to_the_network(monkeypatch):
    sent = []
    tap = vt.Tap("http://127.0.0.1:1", "t", "org_a", "svc", start=True)
    monkeypatch.setattr(tap, "_post", lambda event: sent.append(json.dumps(event)))
    for body in ({"user": {"phone": PHONE, "email": EMAIL}}, {"aadhaar": AADHAAR}, {"card": CARD}, {"note": f"call {PHONE}"}):
        tap.observe("POST", "/x", 200, "request", json.dumps(body).encode())
    tap.flush()
    tap.close()
    assert sent and not any(raw in " ".join(sent) for raw in RAW)


# ---- never harming the application ---------------------------------------------------------------------------------

def test_a_down_server_never_slows_the_caller_and_the_breaker_opens():
    tap = vt.Tap("http://127.0.0.1:1", "t", "org_a", "svc", timeout=0.2, min_interval_seconds=0)
    t = time.perf_counter()
    for i in range(300):
        tap.observe("GET", f"/r{i % 7}", 200, "response", json.dumps({"phone": PHONE, "n": i}).encode())
    assert time.perf_counter() - t < 1.5                      # 300 observations, with the server unreachable
    time.sleep(1.5)
    assert tap.stats["failed"] > 0 and tap._paused_until > 0
    tap.close()


def test_a_full_queue_drops_the_oldest_and_keeps_going():
    tap = make_tap(queue_size=5, min_interval_seconds=0)
    for i in range(20):
        tap.observe("GET", f"/r{i}", 200, "response", json.dumps({"phone": PHONE}).encode())
    assert tap.q.qsize() == 5 and tap.stats["dropped_full"] == 15


class Capture(BaseHTTPRequestHandler):
    got: list = []

    def do_POST(self):
        Capture.got.append((self.path, self.headers.get("Authorization"), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
        self.send_response(200); self.end_headers(); self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


def test_events_reach_a_server_with_the_token_and_the_organization_path():
    Capture.got = []
    srv = HTTPServer(("127.0.0.1", 0), Capture)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        tap = vt.Tap(f"http://127.0.0.1:{srv.server_port}", "secret-token", "org_a", "svc")
        tap.observe("GET", "/a/1", 200, "response", json.dumps({"phone": PHONE}).encode())
        tap.flush()
        tap.close()
        path, auth, event = Capture.got[0]
        assert path == "/v1/org_a/events" and auth == "Bearer secret-token" and event["fields"] == {"phone": "[PHONE_REDACTED]"}
    finally:
        srv.shutdown()


def test_configuration_is_checked():
    with pytest.raises(ValueError):
        make_tap(mode="hash")
    with pytest.raises(ValueError):
        make_tap(mode="scramble")


# ---- ASGI ---------------------------------------------------------------------------------------------------------

def run_asgi(app, method="POST", path="/customers/9", body=b"", headers=None):
    sent = []
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(m):
        sent.append(m)

    asyncio.run(app({"type": "http", "method": method, "path": path, "headers": headers or []}, receive, send))
    return sent


def json_app(response, status=200, content_type=b"application/json", seen_request=None):
    async def app(scope, receive, send):
        msg = await receive()
        if seen_request is not None:
            seen_request.append(msg["body"])
        await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", content_type)]})
        await send({"type": "http.response.body", "body": response})
    return app


def test_asgi_reports_request_and_response_and_leaves_both_intact():
    tap = make_tap(min_interval_seconds=0)
    seen = []
    resp = json.dumps({"user": {"phone": PHONE}}).encode()
    sent = run_asgi(vt.ASGIMiddleware(json_app(resp, seen_request=seen), tap), body=json.dumps({"email": EMAIL}).encode())
    assert sent[1]["body"] == resp and sent[0]["status"] == 200 and seen == [json.dumps({"email": EMAIL}).encode()]
    events = drain(tap)
    assert sorted(e["raw_snippet"].split()[3] for e in events) == ["request", "response"]
    assert not any(raw in json.dumps(events) for raw in RAW)


def test_asgi_ignores_non_json_and_oversize_responses_and_other_scope_types():
    tap = make_tap(min_interval_seconds=0, max_body_bytes=200)
    run_asgi(vt.ASGIMiddleware(json_app(PHONE.encode(), content_type=b"text/plain"), tap))
    run_asgi(vt.ASGIMiddleware(json_app(json.dumps({"phone": PHONE, "pad": "x" * 500}).encode()), tap))
    assert drain(tap) == []

    async def lifespan_app(scope, receive, send):
        return "ok"
    assert asyncio.run(vt.ASGIMiddleware(lifespan_app, tap)({"type": "lifespan"}, None, None)) == "ok"


def test_asgi_does_not_hide_an_application_error_and_still_reports_nothing_wrong():
    tap = make_tap(min_interval_seconds=0)

    async def failing(scope, receive, send):
        await receive()
        raise ValueError("application bug")
    with pytest.raises(ValueError, match="application bug"):
        run_asgi(vt.ASGIMiddleware(failing, tap), body=b"{}")


def test_asgi_overhead_is_small():
    tap = make_tap(min_interval_seconds=0)
    body = json.dumps({"user": {"name": "x", "phone": PHONE}, "items": [{"id": i, "sku": f"s{i}"} for i in range(60)]}).encode()
    plain, wrapped = json_app(body), vt.ASGIMiddleware(json_app(body), tap)
    n = 300

    def timeit(app):
        t = time.perf_counter()
        for _ in range(n):
            run_asgi(app, "GET")
            drain(tap)
        return (time.perf_counter() - t) / n
    extra_ms = (timeit(wrapped) - timeit(plain)) * 1000
    assert extra_ms < 3.0, f"{extra_ms:.2f} ms added per request"


# ---- WSGI ---------------------------------------------------------------------------------------------------------

def run_wsgi(app, body=b"", method="POST", ctype="application/json"):
    environ = {"REQUEST_METHOD": method, "PATH_INFO": "/customers/9", "CONTENT_LENGTH": str(len(body)), "CONTENT_TYPE": ctype,
               "wsgi.input": io.BytesIO(body)}
    status = {}
    result = app(environ, lambda s, h, e=None: status.update(s=s, h=h))
    return status, b"".join(result)


def test_wsgi_reports_both_directions_and_hands_the_body_on_unchanged():
    tap = make_tap(min_interval_seconds=0)
    got = {}
    resp = json.dumps({"phone": PHONE}).encode()

    def app(environ, start_response):
        got["body"] = environ["wsgi.input"].read()
        start_response("200 OK", [("Content-Type", "application/json")])
        return [resp]
    status, out = run_wsgi(vt.WSGIMiddleware(app, tap), body=json.dumps({"email": EMAIL}).encode())
    assert out == resp and got["body"] == json.dumps({"email": EMAIL}).encode() and status["s"] == "200 OK"
    assert len(drain(tap)) == 2


def test_wsgi_leaves_non_json_alone():
    tap = make_tap(min_interval_seconds=0)

    def app(environ, start_response):
        start_response("200 OK", [("Content-Type", "text/html")])
        return [PHONE.encode()]
    _, out = run_wsgi(vt.WSGIMiddleware(app, tap), body=b"x=1", ctype="application/x-www-form-urlencoded")
    assert out == PHONE.encode() and drain(tap) == []


# ---- registering against a server that uses Veritas's own certificate (found in the Mac test) --------------------

def test_register_trusts_the_certificate_it_is_given(monkeypatch, tmp_path):
    import json, ssl, urllib.request
    import veritas_tap as vt
    seen = {}

    class R:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps({"auth_token": "tok", "event_endpoint": "/v1/acme/events"}).encode()

    def fake_urlopen(req, timeout=None, context=None):
        seen["context"] = context
        return R()
    pem = tmp_path / "server.crt"
    monkeypatch.setattr(vt, "_tls_context", lambda ca: ("ctx-for", ca))
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    out = vt.register("https://veritas.example:8000", "key", ca_cert=str(pem))
    assert seen["context"] == ("ctx-for", str(pem)) and out["VERITAS_TAP_CA_CERT"] == str(pem) and out["VERITAS_TAP_ORG"] == "acme"
    monkeypatch.setenv("VERITAS_TAP_CA_CERT", "/etc/from-env.crt")
    vt.register("https://veritas.example:8000", "key")
    assert seen["context"] == ("ctx-for", "/etc/from-env.crt")


def test_an_untrusted_certificate_gets_a_message_that_says_what_to_do(monkeypatch):
    import ssl, urllib.error, urllib.request
    import veritas_tap as vt

    def refuse(req, timeout=None, context=None):
        raise urllib.error.URLError(ssl.SSLCertVerificationError("self-signed certificate"))
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.delenv("VERITAS_TAP_CA_CERT", raising=False)
    try:
        vt.register("https://veritas.example:8000", "key")
        assert False, "should have stopped"
    except SystemExit as e:
        assert "--fetch-cert" in str(e) and "--ca-cert" in str(e)


def test_fetch_server_cert_saves_the_public_certificate(monkeypatch, tmp_path):
    import urllib.request
    import veritas_tap as vt

    class R:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None, context=None: R())
    p = vt.fetch_server_cert("https://veritas.example:8000", str(tmp_path / "server.crt"))
    assert open(p, "rb").read().startswith(b"-----BEGIN CERTIFICATE")
