"""
Veritas Payload Tap for Python services.

A small library that watches the JSON requests and responses of a web service, finds structured personal data in them
(Aadhaar, PAN, phone, e-mail, card) with the same rules the server and the agent use, **masks the values inside your
process**, and reports to Veritas which route carried which kind of data in which field. The report never contains a
value: only placeholders such as [PHONE_REDACTED], the field's path (`user.phone`), the route and the status.

    # FastAPI / Starlette / any ASGI app
    from veritas_tap import Tap, ASGIMiddleware
    tap = Tap.from_env()                       # VERITAS_TAP_URL, VERITAS_TAP_TOKEN, VERITAS_TAP_ORG, VERITAS_TAP_SYSTEM
    app.add_middleware(ASGIMiddleware, tap=tap)

    # Flask / Django / any WSGI app
    from veritas_tap import WSGIMiddleware
    app.wsgi_app = WSGIMiddleware(app.wsgi_app, tap=tap)

Guarantees, in the order they matter:
  * a value is masked before anything is queued or sent; if masking fails, the sample is dropped;
  * the tap never delays, changes or fails a request: work happens after the response, in a background thread, with a
    bounded queue (a full queue drops the oldest sample), short timeouts and a circuit breaker;
  * only JSON bodies up to `max_body_bytes` are looked at; nothing else is read.
It does not find names, and it only sees what passes through the middleware. See docs/PAYLOAD_TAP.md.

Standard library only, plus `veritas_recognizers.py` (the shared rules) next to this file.
"""
from __future__ import annotations

import io
import json
import logging
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Tuple

import veritas_recognizers as vr

__all__ = ["Tap", "ASGIMiddleware", "WSGIMiddleware", "inspect_body", "route_template", "register"]
log = logging.getLogger("veritas.tap")

MAX_DEPTH, MAX_NODES = 8, 2000
_ID_SEGMENT = re.compile(r"^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$")


# --------------------------------------------------------------------------- finding personal data in a body

def _walk(value: Any, path: str, out: List[Tuple[str, str]], budget: List[int], depth: int = 0) -> None:
    if budget[0] <= 0 or depth > MAX_DEPTH:
        return
    budget[0] -= 1
    if isinstance(value, dict):
        for k, v in value.items():
            _walk(v, f"{path}.{k}" if path else str(k), out, budget, depth + 1)
    elif isinstance(value, list):
        for v in value[:200]:
            _walk(v, f"{path}[]", out, budget, depth + 1)
    elif isinstance(value, str):
        out.append((path, value))
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        out.append((path, str(value)))


def inspect_body(body: Any, mode: str = "mask", key: Optional[bytes] = None, max_fields: int = 50) -> Tuple[Dict[str, str], Dict[str, int]]:
    """
    (masked fields, counts per kind) for the leaves of a decoded JSON body that hold personal data. Only such leaves are
    returned, masked, with array positions written as [] so `items[0].phone` and `items[7].phone` are one path.
    """
    leaves: List[Tuple[str, str]] = []
    _walk(body, "", leaves, [MAX_NODES])
    fields: Dict[str, str] = {}
    counts: Dict[str, int] = {}
    for path, value in leaves:
        dets = vr.scan(value) if len(value) <= 4000 else vr.scan(value[:4000])
        if not dets:
            continue
        if mode == "hash" and key:
            out, pos = [], 0
            for start, end, label in vr.covered_spans(dets):
                out += [value[pos:start], vr.hash_token(label, value[start:end], key)]
                pos = end
            out.append(value[pos:])
            masked = "".join(out)
        else:
            masked = vr.mask(value, dets)
        for _s, _e, label in vr.covered_spans(dets):
            counts[label.lower()] = counts.get(label.lower(), 0) + 1
        if len(fields) < max_fields:
            fields[path] = masked[:500]
    return fields, counts


def route_template(path: str, route: Optional[str] = None) -> str:
    """The route as a template. A framework's own template (/customers/{id}) wins; otherwise ids in the path become {id}."""
    if route:
        return route[:200]
    return "/".join("{id}" if _ID_SEGMENT.match(seg) else seg for seg in (path or "/").split("/"))[:200]


# --------------------------------------------------------------------------- the tap

class Tap:
    def __init__(self, url: str, token: str, org: str, system: str, *, mode: str = "mask", hash_key: Optional[bytes] = None,
                 sample_every: int = 1, min_interval_seconds: float = 5.0, max_body_bytes: int = 65536,
                 queue_size: int = 500, timeout: float = 3.0, verify_tls: Any = True, start: bool = True) -> None:
        if mode not in ("mask", "hash"):
            raise ValueError("mode must be mask or hash")
        if mode == "hash" and not hash_key:
            raise ValueError("mode hash needs hash_key (the organization's key, as delivered at registration)")
        self.endpoint = f"{url.rstrip('/')}/v1/{org}/events"
        self.token, self.system, self.mode, self.key = token, system, mode, hash_key
        self.sample_every, self.min_interval, self.max_body = max(1, sample_every), min_interval_seconds, max_body_bytes
        self.timeout, self.verify = timeout, verify_tls
        self.q: "queue.Queue[dict]" = queue.Queue(maxsize=queue_size)
        self.stats = {"seen": 0, "reported": 0, "sent": 0, "dropped_full": 0, "failed": 0, "masking_errors": 0, "skipped_interval": 0}
        self._seen_at: Dict[Tuple[str, str, int, str, Tuple[str, ...]], float] = {}
        self._n = 0
        self._failures = 0
        self._paused_until = 0.0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="veritas-tap", daemon=True)
        if start:
            self._thread.start()

    @classmethod
    def from_env(cls, **kw) -> "Tap":
        env = os.environ
        key = env.get("VERITAS_TAP_HASH_KEY")
        return cls(env["VERITAS_TAP_URL"], env["VERITAS_TAP_TOKEN"], env["VERITAS_TAP_ORG"], env["VERITAS_TAP_SYSTEM"],
                   mode="hash" if key else "mask", hash_key=bytes.fromhex(key) if key else None,
                   verify_tls=env.get("VERITAS_TAP_CA_CERT") or (env.get("VERITAS_TAP_VERIFY", "true").lower() != "false"), **kw)

    # ---- called by the middleware, after the response, never on the request path ----
    def observe(self, method: str, path: str, status: int, direction: str, body: Optional[bytes], route: Optional[str] = None) -> None:
        try:
            self.stats["seen"] += 1
            self._n += 1
            if self._n % self.sample_every or not body or len(body) > self.max_body:
                return
            try:
                decoded = json.loads(body)
            except ValueError:
                return
            try:
                fields, counts = inspect_body(decoded, self.mode, self.key)
            except Exception:
                self.stats["masking_errors"] += 1          # masking failed: the sample is dropped, never sent raw
                return
            if not fields:
                return
            tmpl = route_template(path, route)
            sig = (method, tmpl, status, direction, tuple(sorted(fields)))
            now = time.monotonic()
            with self._lock:
                last = self._seen_at.get(sig)
                if last is not None and now - last < self.min_interval:
                    self.stats["skipped_interval"] += 1
                    return
                if len(self._seen_at) > 5000:
                    self._seen_at.clear()
                self._seen_at[sig] = now
            event = {
                "source_type": "api", "source_kind": "api", "source_system": self.system,
                "raw_snippet": f"{method} {tmpl} {status} {direction} carrying personal data in {len(fields)} field(s)",
                "fields": fields, "schema": 2, "redaction_mode": self.mode,
                "recognizer_pack_version": vr.PACK_VERSION, "agent_detections": counts,
            }
            self.stats["reported"] += 1
            try:
                self.q.put_nowait(event)
            except queue.Full:
                try:
                    self.q.get_nowait()
                except queue.Empty:
                    pass
                self.stats["dropped_full"] += 1
                try:
                    self.q.put_nowait(event)
                except queue.Full:
                    pass
        except Exception:      # the tap must never break the application
            log.debug("tap observe failed", exc_info=True)

    # ---- the background sender ----
    def _post(self, event: dict) -> None:
        req = urllib.request.Request(self.endpoint, data=json.dumps(event).encode("utf-8"), method="POST",
                                     headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        ctx = None
        if self.endpoint.startswith("https"):
            import ssl
            ctx = ssl.create_default_context(cafile=self.verify) if isinstance(self.verify, str) else \
                (ssl.create_default_context() if self.verify else ssl._create_unverified_context())
        with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:      # noqa: S310
            r.read(1024)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                event = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            if time.monotonic() < self._paused_until:
                self.stats["failed"] += 1
                continue
            try:
                self._post(event)
                self.stats["sent"] += 1
                self._failures = 0
            except urllib.error.HTTPError as e:
                self.stats["failed"] += 1
                if e.code in (429, 503):                       # a busy server asks for patience
                    self._paused_until = time.monotonic() + float(e.headers.get("Retry-After", 5) or 5)
                log.debug("tap: server answered %s", e.code)
            except Exception:
                self.stats["failed"] += 1
                self._failures += 1
                if self._failures >= 5:                        # the circuit breaker: stop trying for a minute
                    self._paused_until = time.monotonic() + 60
                    self._failures = 0

    def flush(self, timeout: float = 5.0) -> None:
        """Wait until the queue is empty (for tests and clean shutdown)."""
        end = time.monotonic() + timeout
        while not self.q.empty() and time.monotonic() < end:
            time.sleep(0.02)
        time.sleep(0.05)

    def close(self) -> None:
        self._stop.set()


# --------------------------------------------------------------------------- ASGI

class ASGIMiddleware:
    """For FastAPI, Starlette and other ASGI apps. Buffers JSON bodies up to the limit; everything else streams untouched."""

    def __init__(self, app, tap: Tap, watch_requests: bool = True, watch_responses: bool = True) -> None:
        self.app, self.tap, self.req, self.resp = app, tap, watch_requests, watch_responses

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        req_chunks: List[bytes] = []
        req_size = [0]
        resp_chunks: List[bytes] = []
        info: Dict[str, Any] = {"status": 0, "json": False, "size": 0}

        async def recv():
            message = await receive()
            if self.req and message.get("type") == "http.request" and req_size[0] <= self.tap.max_body:
                chunk = message.get("body", b"")
                req_size[0] += len(chunk)
                if req_size[0] <= self.tap.max_body:
                    req_chunks.append(chunk)
            return message

        async def snd(message):
            if message["type"] == "http.response.start":
                info["status"] = message["status"]
                headers = {k.lower(): v for k, v in message.get("headers", [])}
                info["json"] = b"json" in headers.get(b"content-type", b"")
            elif message["type"] == "http.response.body" and self.resp and info["json"] and info["size"] <= self.tap.max_body:
                chunk = message.get("body", b"")
                info["size"] += len(chunk)
                if info["size"] <= self.tap.max_body:
                    resp_chunks.append(chunk)
            await send(message)

        try:
            await self.app(scope, recv, snd)
        finally:
            try:
                route = getattr(scope.get("route"), "path", None)
                if req_chunks and req_size[0] <= self.tap.max_body:
                    self.tap.observe(scope.get("method", "GET"), scope.get("path", "/"), info["status"], "request", b"".join(req_chunks), route)
                if resp_chunks and info["size"] <= self.tap.max_body:
                    self.tap.observe(scope.get("method", "GET"), scope.get("path", "/"), info["status"], "response", b"".join(resp_chunks), route)
            except Exception:
                log.debug("tap middleware failed", exc_info=True)


# --------------------------------------------------------------------------- WSGI

class WSGIMiddleware:
    """For Flask, Django and other WSGI apps."""

    def __init__(self, app, tap: Tap, watch_requests: bool = True, watch_responses: bool = True) -> None:
        self.app, self.tap, self.req, self.resp = app, tap, watch_requests, watch_responses

    def __call__(self, environ, start_response):
        req_body = b""
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if self.req and 0 < length <= self.tap.max_body and "json" in (environ.get("CONTENT_TYPE") or ""):
            req_body = environ["wsgi.input"].read(length)
            environ["wsgi.input"] = io.BytesIO(req_body)            # hand the application the body again
        captured: Dict[str, Any] = {"status": 0, "json": False}

        def sr(status, headers, exc_info=None):
            captured["status"] = int(str(status).split(" ", 1)[0])
            captured["json"] = any(k.lower() == "content-type" and "json" in v for k, v in headers)
            return start_response(status, headers, exc_info)

        result = self.app(environ, sr)
        chunks: List[bytes] = []
        size = 0

        def generate():
            nonlocal size
            try:
                for chunk in result:
                    if self.resp and captured["json"] and size <= self.tap.max_body:
                        size += len(chunk)
                        if size <= self.tap.max_body:
                            chunks.append(chunk)
                    yield chunk
            finally:
                if hasattr(result, "close"):
                    result.close()
                try:
                    method, path = environ.get("REQUEST_METHOD", "GET"), environ.get("PATH_INFO", "/")
                    if req_body:
                        self.tap.observe(method, path, captured["status"], "request", req_body)
                    if chunks and size <= self.tap.max_body:
                        self.tap.observe(method, path, captured["status"], "response", b"".join(chunks))
                except Exception:
                    log.debug("tap middleware failed", exc_info=True)

        return generate()


# --------------------------------------------------------------------------- registering the tap

def register(url: str, registration_key: str, label: str = "payload-tap", timeout: float = 15.0) -> Dict[str, Any]:
    """Register with the server like an agent does (Agents, Issue Registration Key). Returns what to put in the environment."""
    req = urllib.request.Request(url.rstrip("/") + "/agent/register", method="POST",
                                 data=json.dumps({"registration_key": registration_key, "source_label": label}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310
        data = json.loads(r.read())
    org = data["event_endpoint"].split("/")[2]
    out = {"VERITAS_TAP_URL": url, "VERITAS_TAP_TOKEN": data["auth_token"], "VERITAS_TAP_ORG": org}
    if isinstance(data.get("redaction_key"), dict):
        out["VERITAS_TAP_HASH_KEY (only for hash mode)"] = data["redaction_key"]["key"]
    return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Register a Veritas payload tap and print its settings")
    ap.add_argument("register")
    ap.add_argument("--url", required=True)
    ap.add_argument("--key", required=True, help="a registration key from the Veritas dashboard")
    ap.add_argument("--label", default="payload-tap")
    a = ap.parse_args()
    for k, v in register(a.url, a.key, a.label).items():
        print(f"{k}={v}")
    print("VERITAS_TAP_SYSTEM=<the system name your policy uses>")
