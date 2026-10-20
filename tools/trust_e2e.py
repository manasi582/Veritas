#!/usr/bin/env python3
"""
One story, run end to end on a real server, real agents and the real verifier, proving that redaction, incident
grouping, the observed processing map, rights requests and anchoring work together and not only one at a time
(docs/TRUST_VISIBILITY_PLAN.md section 5; the same story is the pitch demo, docs/DEMO.md).

    python tools/trust_e2e.py --workdir /tmp/e2e [--verifier path/to/veritas-verify] [--noise 6000]
                              [--server-cmd "python -m uvicorn dashboard.server:app --port {port}"]

Needs the server's dependencies (with the language model), `requests`, and the Go verifier (built if --verifier is not
given and `go` is installed). Everything is local: no outside network, no secrets. Exit status 0 only if every
assertion held.
"""
import argparse
import json
import os
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
SERVER_DIR, AGENT_DIR = ROOT / "dpdpa-agent", ROOT / "veritas-agent"
ORG, OTHER = "e2e_corp", "other_org"
# a number nobody asked to erase, so the erasure watch stays quiet in the rules step
OTHER_PHONE = "9812345670"
PHONE, AADHAAR, EMAIL = "9876543210", "2345 6789 0124", "asha.rao@example.com"
PASSWORD = "Violet-Harbor#2468-e2e"
RAW = (PHONE, OTHER_PHONE, AADHAAR, "234567890124", EMAIL, "asha.rao")


class Failure(AssertionError):
    pass


def check(cond, message):
    if not cond:
        raise Failure(message)


def step(name):
    print(f"\n==> {name}", flush=True)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(fn, what, timeout=120, interval=1.0):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            last = fn()
            if last:
                return last
        except Failure:
            raise
        except Exception as e:      # noqa: BLE001 (polling: the thing is not ready yet)
            last = e
        time.sleep(interval)
    raise Failure(f"timed out waiting for {what} (last: {last!r})")


# --------------------------------------------------------------------------- stand-in servers (all local)

class Recorder:
    """A webhook that keeps what it receives (alerts), and a pass-through that keeps what an agent sends (traffic)."""

    def __init__(self):
        self.webhook_bodies, self.traffic = [], []
        outer = self

        class Hook(BaseHTTPRequestHandler):
            def do_POST(self):
                outer.webhook_bodies.append(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8", "replace"))
                self.send_response(200); self.end_headers()

            def log_message(self, *a):
                pass

        self.hook = HTTPServer(("127.0.0.1", 0), Hook)
        threading.Thread(target=self.hook.serve_forever, daemon=True).start()
        self.hook_url = f"http://127.0.0.1:{self.hook.server_port}/hook"
        self.proxy = None

    def start_proxy(self, target):
        outer = self

        class Proxy(BaseHTTPRequestHandler):
            def _go(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.traffic.append((self.command, self.path, body.decode("utf-8", "replace")))
                r = requests.request(self.command, target + self.path, data=body, timeout=60,
                                     headers={k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length")})
                self.send_response(r.status_code)
                for k in ("Content-Type", "Retry-After"):
                    if k in r.headers:
                        self.send_header(k, r.headers[k])
                self.send_header("Content-Length", str(len(r.content)))
                self.end_headers()
                self.wfile.write(r.content)

            do_POST = do_GET = _go

            def log_message(self, *a):
                pass

        self.proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.proxy.server_port}"


# --------------------------------------------------------------------------- the story

class E2E:
    def __init__(self, a):
        self.a = a
        self.work = Path(a.workdir).resolve()
        self.data = self.work / "data"
        self.w1, self.w2 = self.work / "witness1", self.work / "witness2"
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.rec = Recorder()
        self.server = None
        self.agents = []
        self.env = {}

    # ---- plumbing --------------------------------------------------------------------------------------
    def prepare(self):
        if self.work.exists():
            shutil.rmtree(self.work)
        for d in (self.data, self.w1, self.w2, self.work / "logs"):
            d.mkdir(parents=True)
        (self.work / "anchoring.yaml").write_text(
            "anchoring:\n  enabled: true\n  interval_minutes: 0.5\n  every_n_records: 50\n  min_witnesses: 2\n  sinks:\n"
            f"    - type: file\n      path: {self.w1}\n    - type: file\n      path: {self.w2}\n")
        self.env = {**os.environ, "VERITAS_DATA_DIR": str(self.data), "VERITAS_SECURE_COOKIES": "false",
                    "VERITAS_JWT_SECRET": "e2e-" + uuid.uuid4().hex, "VERITAS_ANCHOR_CONFIG": str(self.work / "anchoring.yaml"),
                    "VERITAS_INCIDENT_GRACE_SECONDS": "3", "VERITAS_DETECTION_WORKERS": os.environ.get("VERITAS_DETECTION_WORKERS", "2"),
                    "VERITAS_ALERT_WEBHOOK_URL": self.rec.hook_url, "VERITAS_ALERT_MIN_SEVERITY": "HIGH",
                    "FORCE_LLM_FALLBACK": "1", "PYTHONUNBUFFERED": "1"}

    def make_users(self):
        """The first administrators, made the way a test harness may: straight into the user database, before the server starts."""
        code = (f"import sys; sys.path.insert(0, {str(SERVER_DIR)!r})\n"
                "from passlib.context import CryptContext\n"
                "from user_store.store import get_user_store\nfrom user_store.models import UserRole\n"
                f"h = CryptContext(schemes=['bcrypt']).hash({PASSWORD!r})\ns = get_user_store()\n"
                "for name, role in (('e2e_super', UserRole.SUPER_ADMIN), ('e2e_admin', UserRole.COMPLIANCE_ADMIN), ('e2e_viewer', UserRole.VIEWER)):\n"
                "    u = s.create_user(name, name + '@e2e.test', h, role)\n"
                f"    s.grant_org_access(u.user_id, {ORG!r}); s.grant_org_access(u.user_id, {OTHER!r})\n")
        subprocess.run([sys.executable, "-c", code], env=self.env, check=True, cwd=SERVER_DIR)

    def start_server(self, extra_env=None):
        cmd = self.a.server_cmd.format(port=self.port)
        self.server_log = open(self.work / "server.log", "ab")
        self.server = subprocess.Popen(shlex.split(cmd), cwd=SERVER_DIR, env={**self.env, **(extra_env or {})},
                                       stdout=self.server_log, stderr=subprocess.STDOUT)
        def up():
            check(self.server.poll() is None, "the server process exited while starting (see its log below)")
            return requests.get(self.base + "/health", timeout=3).ok
        wait_for(up, "the server to answer", timeout=300)

    def stop_server(self):
        if self.server and self.server.poll() is None:
            self.server.send_signal(signal.SIGINT if os.name != "nt" else signal.CTRL_BREAK_EVENT)
            try:
                self.server.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.server.kill()
        self.server = None

    def login(self, name):
        s = requests.Session()
        r = s.post(self.base + "/api/auth/login", data={"username": name, "password": PASSWORD}, timeout=30)
        check(r.status_code == 200, f"{name} could not sign in: {r.status_code} {r.text[:200]}")
        return s

    def get(self, s, path, **kw):
        r = s.get(self.base + path, timeout=60, **kw)
        check(r.ok, f"GET {path} -> {r.status_code} {r.text[:300]}")
        return r

    def post(self, s, path, expect=(200, 201), **kw):
        r = s.post(self.base + path, timeout=60, **kw)
        check(r.status_code in expect, f"POST {path} -> {r.status_code} {r.text[:300]}")
        return r

    def new_agent_token(self, admin, org):
        key = self.post(admin, "/agents/issue-key", json={"org_id": org}).json()["key"]
        return key

    def start_agent(self, name, org, system, address, redaction=None, source_type="file", source=None):
        admin = self.admins
        key = self.new_agent_token(admin, org)
        log = self.work / "logs" / f"{name}.log"
        log.write_text("")
        cfg = {"veritas_address": address, "registration_key": key, "source_label": name,
               "state_dir": str(self.work / f"state-{name}"), "sources": [source or {"type": source_type, "path": str(log), "source_system": system}]}
        if redaction:
            cfg["redaction"] = redaction
        (self.work / f"{name}.yaml").write_text(json.dumps(cfg))        # JSON is YAML
        (self.work / f"state-{name}").mkdir(exist_ok=True)
        proc = subprocess.Popen([sys.executable, str(AGENT_DIR / "agent.py"), "--config", str(self.work / f"{name}.yaml")],
                                cwd=AGENT_DIR, env={**os.environ, "PYTHONPATH": str(AGENT_DIR)},
                                stdout=open(self.work / f"{name}.out", "ab"), stderr=subprocess.STDOUT)
        self.agents.append(proc)
        return log

    def write_lines(self, log, lines):
        with open(log, "a", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")

    def verdict_count(self, s, org=ORG):
        return self.get(s, f"/api/{org}/verdicts").json()["count"]

    def incidents(self, s, **params):
        return self.get(s, f"/v1/{ORG}/incidents", params=params).json()

    def flow_node(self, s, system):
        return next((n for n in self.get(s, f"/v1/{ORG}/flows").json()["nodes"] if n["id"] == system), None)

    # ---- the steps -------------------------------------------------------------------------------------
    def run(self):
        self.prepare()
        step("setup: server with anchoring to two witnesses, incidents, flows and lookup; users; an organization with owners")
        self.make_users()
        self.start_server()
        self.admins = self.login("e2e_admin")
        self.super = self.login("e2e_super")
        self.viewer = self.login("e2e_viewer")
        fields = lambda system, cat: [{"field_name": f"{cat}_field", "pii_category": cat, "declared_purpose": "service",
                                       "consent_scope": "service", "retention_days": 365, "source_system": system}]
        cfg = {"org_id": ORG, "fields": fields("order-service", "phone") + fields("support-ticketing", "phone") +
                                        fields("marketing-service", "phone") + fields("noisy-service", "phone") +
                                        [{"field_name": "phone", "pii_category": "phone", "declared_purpose": "service", "consent_scope": "service",
                                          "retention_days": 30, "source_system": "retention-demo", "data_since": "2025-01-01"}],
               "owners": {"order-service": {"team": "Orders", "email": "orders@e2e.test", "slack_channel": "#orders"},
                          "support-ticketing": {"team": "Support", "email": "support@e2e.test"},
                          "marketing-service": {"team": "Marketing", "email": "marketing@e2e.test"},
                          "noisy-service": {"team": "Platform", "email": "platform@e2e.test"},
                          "retention-demo": {"team": "Data", "email": "data@e2e.test"}},
               "notices": [{"notice_id": "n-core", "version": "3", "title": "Customer privacy notice", "effective_from": "2026-01-01",
                            "review_by": "2030-01-01", "data_categories": ["phone"], "systems": ["*"], "languages": ["en", "hi"]}]}
        check(self.post(self.admins, f"/v1/orgs/{ORG}/config", json=cfg).json().get("status") == "ok", "the organization was not accepted")
        other = {"org_id": OTHER, "fields": fields("billing", "phone")}
        check(self.post(self.admins, f"/v1/orgs/{OTHER}/config", json=other).json().get("status") == "ok", "the second organization was not accepted")
        health = self.get(self.super, "/api/system/health").json()
        anchoring = health["checks"].get("anchoring", {})
        check(anchoring.get("status") == "ok" and len(anchoring.get("witnesses") or []) == 2 and not anchoring.get("single_witness"), f"anchoring is not on with two witnesses: {anchoring}")

        proxy = self.rec.start_proxy(self.base)
        self.log_order = self.start_agent("agent-monitor", ORG, "order-service", self.base)
        self.log_support = self.start_agent("agent-redact", ORG, "support-ticketing", proxy, redaction={
            "mode": "monitor", "categories": {"aadhaar": "mask", "phone": "hash", "email": "mask"}, "fail_closed": True,
            "tee_file": str(self.work / "logs" / "masked.log")})
        agents = wait_for(lambda: (lambda a: a if len(a) == 2 and all(x.get("last_heartbeat_at") for x in a) else None)(
            self.get(self.admins, f"/agents?org_id={ORG}").json()["agents"]), "both agents to register and report")

        step("redaction (F5): the masking agent sends no raw value, and the dashboard knows its mode")
        self.write_lines(self.log_support, [f"2026-10-20 10:00:01 INFO ticket 1 callback to {PHONE} aadhaar {AADHAAR} mail {EMAIL} done"])
        self.write_lines(self.log_order, [f"2026-10-20 10:00:02 INFO order 1 confirmation sent to {PHONE}"])
        wait_for(lambda: self.verdict_count(self.admins) >= 2, "the first findings")
        events = [b for m, p, b in self.rec.traffic if p.endswith("/events")]
        check(events, "the proxy saw no events from the masking agent")
        for body in events:
            for raw in RAW:
                check(raw not in body, f"the masking agent sent a raw value: {raw!r}")
        check("[AADHAAR_REDACTED]" in "".join(events) and "[PHONE#" in "".join(events) and "[EMAIL_REDACTED]" in "".join(events),
              "the masked line does not show placeholders")
        masked = (self.work / "logs" / "masked.log").read_text()
        check(not any(raw in masked for raw in RAW) and "[PHONE#" in masked, "the masked copy is not masked")
        wait_for(lambda: self.get(self.admins, f"/agents?org_id={ORG}").json()["agents"] and
                        {a["source_label"]: ((a.get("health") or {}).get("redaction") or {}).get("mode")
                         for a in self.get(self.admins, f"/agents?org_id={ORG}").json()["agents"]}.get("agent-redact") == "mixed",
                        "the dashboard to show the masking agent's mode")
        blob = json.dumps([self.get(self.admins, f"/api/{ORG}/verdicts").json(), self.incidents(self.admins),
                           self.get(self.admins, f"/v1/{ORG}/flows").json()])
        check(not any(raw in blob for raw in RAW), "a raw value is visible through the API")

        step("detection and grouping (F3): a noisy service writes thousands of near-identical lines")
        noisy_key = self.new_agent_token(self.admins, ORG)
        tok = requests.post(self.base + "/agent/register", json={"registration_key": noisy_key, "source_label": "noisy"}, timeout=30).json()["auth_token"]
        templates = ["debug cache refresh for tenant {n} took {n} ms trace {u} aadhaar " + AADHAAR,
                     "warn retry {n} of 5 for session {u} aadhaar " + AADHAAR,
                     "error payment worker {n} lost connection after {n} ms aadhaar " + AADHAAR,
                     "info reconcile batch {n} finished in {n} ms aadhaar " + AADHAAR]
        total = self.a.noise
        sess = requests.Session()

        def send(i):
            line = templates[i % 4].format(n=i, u=uuid.uuid4())
            for attempt in range(60):
                r = sess.post(f"{self.base}/v1/{ORG}/events", headers={"Authorization": f"Bearer {tok}"}, timeout=60,
                              json={"source_type": "log", "source_system": "noisy-service", "raw_snippet": line})
                if r.status_code == 200:
                    return True
                if r.status_code in (429, 503):
                    time.sleep(float(r.headers.get("Retry-After", 1)))
                    continue
                return False
            return False

        started = time.time()
        with ThreadPoolExecutor(8) as ex:
            ok = sum(ex.map(send, range(total)))
        print(f"    {ok}/{total} lines accepted in {time.time() - started:.0f} s")
        check(ok == total, f"only {ok} of {total} lines were accepted")
        summary = self.get(self.admins, f"/v1/{ORG}/incidents/summary").json()
        check(summary["verdicts"] >= total, f"verdicts {summary['verdicts']} < lines {total}")
        noisy = [i for i in self.incidents(self.admins, limit=100)["incidents"] if i["source_system"] == "noisy-service"]
        for i in sorted(noisy, key=lambda x: -x["count"]):
            print(f"    INC-{i['number']:<3} {i['rule_id']:13} {i['count']:6}  {i['template'][:90]}")
        # four kinds of line; the language model may add findings of its own (a word taken for a name), each of which
        # groups by its own rule and wording, so "a handful" means far fewer incidents than lines, not exactly four
        check(1 <= len(noisy) <= 40 and len(noisy) * 100 <= total, f"the noisy service made {len(noisy)} incidents from {total} lines")
        check(sum(i["count"] for i in noisy) >= total, "the incident counts do not cover the lines sent")
        check(all(i["owner"] and i["owner"]["team"] == "Platform" for i in noisy), "an incident has no owner")
        check(all(sum(i["sparkline"]) == i["count"] for i in noisy), "a sparkline does not match its count (the run must finish within a day)")
        print(f"    {summary['verdicts']} findings -> {summary['incidents']} incidents")
        check(self.get(self.admins, f"/api/{ORG}/verify-chain").json()["valid"], "the chain is not valid after the flood")

        step("flow map (F2): a system shows up, its node is red while an incident is open")
        sup = self.flow_node(self.admins, "support-ticketing")
        check(sup and {c["category"] for c in sup["observed"]} >= {"aadhaar", "phone", "email"}, f"the masked agent's categories are missing: {sup}")
        check(self.flow_node(self.admins, "noisy-service")["status"] == "red", "a system with an open incident is not red")
        record = self.get(self.admins, f"/v1/{ORG}/flows/export").text
        check(not any(raw in record for raw in RAW) and "Record of observed processing" in record, "the processing record holds a raw value")

        step("schema watch (R4): a new personal-data column in a database log, with no declaration, is a finding")
        db_log = self.start_agent("agent-db", ORG, "loan-db", self.base, source_type="db_schema_log")
        db_log_path = db_log
        wait_for(lambda: any(a["source_label"] == "agent-db" and a.get("last_heartbeat_at")
                             for a in self.get(self.admins, f"/agents?org_id={ORG}").json()["agents"]), "the database agent to report")
        time.sleep(2)           # the agent starts reading at the end of the file
        self.write_lines(db_log_path, [
            "2026-10-20 12:00:00 UTC LOG:  statement: INSERT INTO customers (phone) VALUES ('" + PHONE + "')",
            "2026-10-20 12:00:01 UTC LOG:  statement: ALTER TABLE customers ADD COLUMN aadhaar_no varchar(12);",
            "2026-10-20 12:00:02 UTC LOG:  statement: CREATE TABLE loan_applicants (",
            "\tid serial,", "\tdate_of_birth date,", "\tnote text", ");"])
        found = wait_for(lambda: [v for v in self.get(self.admins, f"/api/{ORG}/verdicts").json()["verdicts"]
                                  if v["source_system"] == "loan-db" and v["field"] == "customers.aadhaar_no"], "the schema finding")
        check(found[0]["rule_id"] == "PURPOSE_001", f"the schema finding has the wrong rule: {found[0]['rule_id']}")
        listing = self.get(self.admins, f"/v1/{ORG}/schema").json()
        columns = {(c["table_name"], c["column_name"]): c["status"] for c in listing["changes"]}
        check(columns.get(("customers", "aadhaar_no")) == "undeclared" and columns.get(("loan_applicants", "date_of_birth")) == "undeclared",
              f"the schema changes are not listed as expected: {columns}")
        check(not any(raw in json.dumps(listing) for raw in RAW), "the schema listing holds a raw value")
        check(all(v["field"] != "customers.phone" for v in self.get(self.admins, f"/api/{ORG}/verdicts").json()["verdicts"]
                  if v["source_system"] == "loan-db"), "an INSERT statement was treated as schema")
        node = self.flow_node(self.admins, "loan-db")
        check(node and any("schema" in c["kinds"] for c in node["observed"]), f"the data map does not show the schema source: {node}")

        step("payload tap (R3): an API response carries personal data in an undeclared field; the tap masks it in the service")
        sys.path.insert(0, str(ROOT / "veritas-sdk" / "python"))
        import asyncio
        import veritas_tap
        tap = veritas_tap.Tap(self.base, tok, ORG, "customer-api", min_interval_seconds=0)
        leaked = json.dumps({"user": {"aadhaar_no": AADHAAR, "city": "Pune"}, "items": [{"mobile": PHONE}]}).encode()

        async def customers(scope, receive, send):
            await receive()
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": leaked})
        sent_by_app = []

        async def send(m):
            sent_by_app.append(m)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}
        asyncio.run(veritas_tap.ASGIMiddleware(customers, tap)({"type": "http", "method": "GET", "path": "/customers/42", "headers": []}, receive, send))
        check(sent_by_app[1]["body"] == leaked, "the tap changed the application's response")
        tap.flush()
        api_findings = wait_for(lambda: [v for v in self.get(self.admins, f"/api/{ORG}/verdicts").json()["verdicts"]
                                         if v["source_system"] == "customer-api"], "the finding from the tapped response")
        check("user.aadhaar_no" in {v["field"] for v in api_findings}, f"the field is not named in the findings: {[v['field'] for v in api_findings]}")
        check(not any(raw in json.dumps(api_findings) for raw in RAW), "a raw value reached the server through the tap")
        node = self.flow_node(self.admins, "customer-api")
        check(node and any("api" in c["kinds"] for c in node["observed"]), f"the data map does not show the API source: {node}")
        spec = self.work / "openapi.json"
        spec.write_text(json.dumps({"paths": {"/x": {"get": {"responses": {"200": {"content": {"application/json": {"example": {"phone": PHONE}}}}}}}}}))
        gate = subprocess.run([sys.executable, str(ROOT / "veritas-sdk" / "python" / "veritas_gate.py"), str(spec)], capture_output=True, text=True)
        check(gate.returncode == 1 and PHONE not in gate.stdout, "the pipeline gate did not fail on personal data in an example")
        tap.close()

        step("retention review (R7): a declared period has run out, data is still seen, the owner confirms, and it shows if the data keeps coming")
        send_retention = lambda: requests.post(f"{self.base}/v1/{ORG}/events", headers={"Authorization": f"Bearer {tok}"}, timeout=60,
                                               json={"source_type": "log", "source_system": "retention-demo", "raw_snippet": f"export row for {PHONE}"})
        check(send_retention().status_code == 200, "the retention-demo event was refused")
        def retention_item():
            items = self.get(self.admins, f"/v1/{ORG}/retention").json()["items"]
            return next((i for i in items if i["system"] == "retention-demo"), None)
        item = wait_for(lambda: (lambda i: i if i and i["status"] == "overdue" else None)(retention_item()), "the retention review to show the period as overdue")
        check(item["clock_source"] == "policy data_since" and item["owner"]["team"] == "Data", f"the review lacks its clock or owner: {item}")
        task = self.post(self.admins, f"/v1/{ORG}/retention/tasks", json={"systems": ["retention-demo"]}).json()
        check(task["type"] == "retention" and task["tasks"][0]["owner"].startswith("Data"), "the retention task has no owner")
        check(self.post(self.admins, f"/v1/{ORG}/retention/tasks", expect=(400,), json={"systems": ["retention-demo"]}).status_code == 400, "a duplicate task was accepted")
        done = self.post(self.admins, f"/v1/{ORG}/requests/{task['request_id']}/tasks/retention-demo/confirm", json={"note": "purged"}).json()
        check(done["status"] == "CLOSED" and not done["watching"], "the retention task did not close cleanly")
        check(send_retention().status_code == 200, "the second retention-demo event was refused")
        again = wait_for(lambda: (lambda i: i if i and i["status"] == "overdue" and i["task_request_id"] is None else None)(retention_item()),
                         "the period to be overdue again after the data kept arriving")
        check(self.get(self.admins, f"/api/{ORG}/verify-chain").json()["valid"], "the chain is not valid after the retention task")

        step("notice registry (R8): a kind of data no current notice covers is a finding, once; recording a notice closes the gap")
        cov = self.get(self.admins, f"/v1/{ORG}/notices").json()
        check(cov["enabled"] and cov["notices"][0]["status"] == "current", f"the notice is not shown as current: {cov['notices']}")
        uncovered = {(o["system"], o["category"]) for o in cov["observed"] if not o["covered"]}
        check(("noisy-service", "aadhaar") in uncovered and ("noisy-service", "phone") not in uncovered, f"coverage is wrong: {uncovered}")
        gaps = wait_for(lambda: [v for v in self.get(self.admins, f"/api/{ORG}/verdicts").json()["verdicts"] if v["rule_id"] == "NOTICE_001"],
                        "the NOTICE_001 findings")
        check(any(v["source_system"] == "noisy-service" and v["field"] == "aadhaar" for v in gaps), "no NOTICE_001 for aadhaar in noisy-service")
        before = len(gaps)
        requests.post(f"{self.base}/v1/{ORG}/events", headers={"Authorization": f"Bearer {tok}"}, timeout=60,
                      json={"source_type": "log", "source_system": "noisy-service", "raw_snippet": f"another line with aadhaar {AADHAAR}"})
        after = len([v for v in self.get(self.admins, f"/api/{ORG}/verdicts").json()["verdicts"] if v["rule_id"] == "NOTICE_001"
                     and v["source_system"] == "noisy-service" and v["field"] == "aadhaar"])
        check(after == 1, f"the same gap was raised {after} times")
        policy = self.get(self.admins, f"/v1/orgs/{ORG}/config").json()
        policy = policy.get("config", policy)
        policy["notices"].append({"notice_id": "n-kyc", "version": "1", "effective_from": "2026-02-01", "data_categories": ["aadhaar"],
                                  "systems": ["noisy-service"]})
        check(self.post(self.admins, f"/v1/orgs/{ORG}/config", json=policy).json().get("status") == "ok", "the policy with the new notice was not accepted")
        cov = self.get(self.admins, f"/v1/{ORG}/notices").json()
        check(next(o for o in cov["observed"] if o["system"] == "noisy-service" and o["category"] == "aadhaar")["covered"], "the new notice did not close the gap")
        check(not any(raw in json.dumps(cov) for raw in RAW), "the notice review holds a raw value")

        step("streaming receivers (R2): an OpenTelemetry log export and a syslog message are judged like any log line")
        otlp = {"resourceLogs": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "checkout-otel"}}]},
                                  "scopeLogs": [{"logRecords": [{"timeUnixNano": str(int(time.time() * 1e9)), "severityText": "INFO",
                                                                "body": {"stringValue": f"callback to {PHONE} failed"}}]}]}]}
        r = requests.post(f"{self.base}/v1/{ORG}/otlp/logs", json=otlp, headers={"Authorization": f"Bearer {tok}"}, timeout=60)
        check(r.status_code == 200 and r.json() == {}, f"the OTLP export was refused: {r.status_code} {r.text[:200]}")
        r = requests.post(f"{self.base}/v1/{ORG}/otlp/logs", data=b"\x0a\x00", headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/x-protobuf"}, timeout=60)
        check(r.status_code == 415, "OTLP over protobuf should be refused with a clear message")
        syslog_port = free_port()
        self.start_agent("agent-syslog", ORG, "edge-gateway", self.base, source={"type": "syslog", "source_system": "edge-gateway", "port": syslog_port, "protocol": "udp"})
        wait_for(lambda: any(a["source_label"] == "agent-syslog" and a.get("last_heartbeat_at") for a in self.get(self.admins, f"/agents?org_id={ORG}").json()["agents"]),
                 "the syslog agent to report")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(3):
            sock.sendto(f"<14>1 2026-10-20T10:00:00Z gw app - - - login failed for {PHONE}".encode(), ("127.0.0.1", syslog_port))
            time.sleep(0.5)
        for system in ("checkout-otel", "edge-gateway"):
            wait_for(lambda s=system: [v for v in self.get(self.admins, f"/api/{ORG}/verdicts").json()["verdicts"] if v["source_system"] == s],
                     f"the finding from {system}")
        kinds = {c["kinds"][0] for n in self.get(self.admins, f"/v1/{ORG}/flows").json()["nodes"] if n["id"] == "checkout-otel" for c in n["observed"]}
        check(kinds == {"otlp"}, f"the data map does not show the OTLP source: {kinds}")

        step("resolution and recurrence (F3): resolve, wait out the grace period, see it come back")
        target = max((i for i in noisy if i["rule_id"] == "EXPOSURE_001"), key=lambda i: i["count"])
        self.post(self.admins, f"/v1/{ORG}/incidents/{target['incident_id']}/status", json={"status": "ACKNOWLEDGED"})
        self.post(self.admins, f"/v1/{ORG}/incidents/{target['incident_id']}/status", json={"status": "RESOLVED", "reason": "fixed in 4.2"})
        time.sleep(4)
        line = templates[0].format(n=999_999, u=uuid.uuid4())
        for t in templates:        # whichever incident it was, a matching line reopens it
            send_line = t.format(n=999_999, u=uuid.uuid4())
            requests.post(f"{self.base}/v1/{ORG}/events", headers={"Authorization": f"Bearer {tok}"}, timeout=60,
                          json={"source_type": "log", "source_system": "noisy-service", "raw_snippet": send_line})
        again = self.get(self.admins, f"/v1/{ORG}/incidents/{target['incident_id']}").json()
        check(again["status"] == "OPEN" and again["recurred"], f"the incident did not reopen as recurred: {again['status']}")
        export = self.get(self.admins, f"/v1/{ORG}/evidence/export").text.splitlines()
        kinds = [(json.loads(x).get("record_type"), (json.loads(x).get("body") or {}).get("action")) for x in export[1:]]
        check(("INCIDENT_EVENT", "RECUR") in kinds and kinds.count(("INCIDENT_EVENT", "STATUS")) >= 2, "the status changes are not chain events")

        step("rights request (F4): look up the phone number, open an erasure request, owners confirm, signed record")
        found = self.post(self.admins, f"/v1/{ORG}/subjects/lookup", json={"category": "phone", "identifier": "+91 98765 43210"}).json()
        systems = {s["system"] for s in found["systems"]}
        check({"order-service", "support-ticketing"} <= systems, f"the lookup missed a system (hash token or clear): {systems}")
        check(self.post(self.viewer, f"/v1/{ORG}/subjects/lookup", expect=(403,), json={"category": "phone", "identifier": PHONE}).status_code == 403, "a viewer could look up")
        req = self.post(self.admins, f"/v1/{ORG}/requests", json={"type": "erasure", "requester_ref": "TKT-E2E-1",
                        "identifiers": [{"category": "phone", "identifier": PHONE}]}).json()
        check({t["system"] for t in req["tasks"]} >= {"order-service", "support-ticketing"}, "tasks are not generated per system")
        check(next(t for t in req["tasks"] if t["system"] == "order-service")["owner"].startswith("Orders"), "a task has no owner")
        for t in req["tasks"]:
            req = self.post(self.admins, f"/v1/{ORG}/requests/{req['request_id']}/tasks/{t['system']}/confirm", json={"note": "e2e"}).json()
        check(req["status"] == "CLOSED" and req["watching"], "the request did not close into a watch")
        rec = self.get(self.admins, f"/v1/{ORG}/requests/{req['request_id']}/record.json").json()
        pdf = self.get(self.admins, f"/v1/{ORG}/requests/{req['request_id']}/record.pdf").content
        sys.path.insert(0, str(SERVER_DIR))
        from subject_lookup import record as subject_record
        check(subject_record.verify(rec["record"], rec["signature"]), "the record's signature does not verify")
        check(pdf.startswith(b"%PDF") and all(raw.encode() not in pdf for raw in RAW), "the PDF record is wrong")
        check(len(rec["record"]["chain"]["request_events"]) >= 3 and all(len(e["chain_hash"]) == 64 for e in rec["record"]["chain"]["request_events"]),
              "the record does not reference chain entries")
        audit = self.get(self.super, "/api/audit/logs", params={"limit": 500}).json()
        entries = [e for e in audit.get("entries", []) if e.get("action") == "SUBJECT_LOOKUP"]
        check(entries and not any(raw in json.dumps(entries) for raw in RAW), "the lookup audit log is missing or holds the identifier")

        step("resurrection (F4): the same phone number appears again; ERASURE_001 and an alert")
        self.write_lines(self.log_support, [f"2026-10-20 11:00:00 INFO ticket 9 callback to +91 {PHONE} done"])
        verdicts = wait_for(lambda: [v for v in self.get(self.admins, f"/api/{ORG}/verdicts").json()["verdicts"] if v["rule_id"] == "ERASURE_001"],
                            "ERASURE_001 to fire (through the hashed token)")
        self.write_lines(self.log_order, [f"2026-10-20 11:00:01 INFO order 2 reminder sent to {PHONE}"])
        wait_for(lambda: len([v for v in self.get(self.admins, f"/api/{ORG}/verdicts").json()["verdicts"] if v["rule_id"] == "ERASURE_001"]) >= 2,
                 "ERASURE_001 to fire again (the identifier in clear)")
        wait_for(lambda: any("ERASURE_001" in b for b in self.rec.webhook_bodies), "the alert for ERASURE_001", timeout=180, interval=3)

        step("anchoring (F1): checkpoints witnessed by both sinks, then export")
        for org in (ORG, OTHER):
            if org == OTHER:
                tok2 = requests.post(self.base + "/agent/register", json={"registration_key": self.new_agent_token(self.admins, OTHER),
                                     "source_label": "billing-agent"}, timeout=30).json()["auth_token"]
                for i in range(8):
                    requests.post(f"{self.base}/v1/{OTHER}/events", headers={"Authorization": f"Bearer {tok2}"}, timeout=60,
                                  json={"source_type": "log", "source_system": "billing", "raw_snippet": f"invoice {i} aadhaar {AADHAAR}"})
            self.post(self.admins, f"/v1/{org}/anchors/run", expect=(200,))
        for org in (ORG, OTHER):
            wait_for(lambda: all(c["status"] == "WITNESSED" for c in self.get(self.admins, f"/v1/{org}/anchors").json()["checkpoints"])
                     and self.get(self.admins, f"/v1/{org}/anchors").json()["checkpoints"], f"{org}'s checkpoints to be witnessed")
        self.exports = {}
        for org in (ORG, OTHER):
            d = self.work / f"export-{org}"
            d.mkdir()
            (d / "evidence.jsonl").write_text(self.get(self.admins, f"/v1/{org}/evidence/export").text)
            (d / "cps.jsonl").write_text(self.get(self.admins, f"/v1/{org}/anchors/export").text)
            (d / "veritas.pub").write_text(self.get(self.admins, f"/v1/{org}/anchors/pubkey").text)
            self.exports[org] = d
        v = self.verifier()
        for org in (ORG, OTHER):
            code, out = self.verify(v, self.exports[org])
            check(code == 0, f"the verifier rejected clean evidence of {org}: {out}")
        print("    the verifier accepts the clean export of both organizations")

        step("rules: approved overlays and exceptions, a review task, the agent's redaction floor, and why a finding fired")
        rules = self.get(self.admins, f"/v1/{ORG}/rules").json()
        check([r["rule_id"] for r in rules["rules"]] == ["EXPOSURE_001", "PURPOSE_001", "RETENTION_001", "LINKAGE_001", "ERASURE_001", "NOTICE_001"], "the rules are not the six")
        check(not rules["self_approval_allowed"], "self-approval is allowed although two administrators exist")
        check(all("violation" not in r["summary"].lower() for r in rules["rules"]), "a rule's summary says violation")
        check(self.post(self.admins, f"/v1/{ORG}/rules/changes", expect=(400,), json={"kind": "OVERLAY", "target": "EXPOSURE_001", "setting": {"actions": ["block"]}}).status_code == 400,
              "a block action was accepted")
        change = self.post(self.admins, f"/v1/{ORG}/rules/changes", json={"kind": "OVERLAY", "target": "EXPOSURE_001", "reason": "owners review log exposure",
                                                                         "setting": {"actions": ["alert", "require_review"]}}).json()
        self.post(self.admins, f"/v1/{ORG}/rules/changes/{change['change_id']}/approve", expect=(400,), json={})      # not the proposer
        check(self.post(self.super, f"/v1/{ORG}/rules/changes/{change['change_id']}/approve", json={}).json()["status"] == "APPROVED", "the second administrator could not approve")
        floor = self.post(self.admins, f"/v1/{ORG}/rules/changes", json={"kind": "OVERLAY", "target": "PURPOSE_001", "reason": "mask phone numbers at the source",
                                                                        "setting": {"actions": ["alert", "redact"], "redact_kinds": {"phone": "mask"}}}).json()
        self.post(self.super, f"/v1/{ORG}/rules/changes/{floor['change_id']}/approve", json={})

        key = self.new_agent_token(self.admins, ORG)
        tok2 = requests.post(self.base + "/agent/register", json={"registration_key": key, "source_label": "rules-demo"}, timeout=30).json()["auth_token"]

        def send_line(system, line):
            r = requests.post(f"{self.base}/v1/{ORG}/events", headers={"Authorization": f"Bearer {tok2}"}, timeout=60,
                              json={"source_type": "log", "source_system": system, "raw_snippet": line})
            check(r.status_code == 200, f"event refused: {r.status_code} {r.text[:200]}")

        def open_reviews():
            return [q for q in self.get(self.admins, f"/v1/{ORG}/requests").json()["requests"] if q["type"] == "review" and q["status"] == "OPEN"]

        check(not open_reviews(), "a review task existed before any rule asked for one")
        send_line("order-service", "debug rules demo first line phone " + OTHER_PHONE)
        reviews = open_reviews()
        check(len(reviews) == 1 and reviews[0]["tasks"][0]["system"] == "order-service" and reviews[0]["tasks"][0]["owner"].startswith("Orders"),
              "the require_review action did not open one task for the owner")
        send_line("order-service", "debug rules demo first line phone " + OTHER_PHONE)
        check(len(open_reviews()) == 1, "a second finding of the same incident opened a second review task")
        done = self.post(self.admins, f"/v1/{ORG}/requests/{reviews[0]['request_id']}/tasks/order-service/confirm", json={"note": "e2e"}).json()
        check(done["status"] == "CLOSED", "confirming the review task did not close it")

        before = self.verdict_count(self.admins)
        send_line("exception-demo", "debug exception demo phone " + OTHER_PHONE)
        check(self.verdict_count(self.admins) == before + 1, "the finding before the exception was not stored")
        exc = self.post(self.admins, f"/v1/{ORG}/rules/changes", json={"kind": "EXCEPTION", "reason": "known debug logging, being removed",
              "setting": {"rule_id": "EXPOSURE_001", "system": "exception-demo", "field": "*", "reason": "known debug logging, being removed",
                          "owner": "Platform team", "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()}}).json()
        self.post(self.super, f"/v1/{ORG}/rules/changes/{exc['change_id']}/approve", json={})
        send_line("exception-demo", "debug exception demo again phone " + OTHER_PHONE)
        check(self.verdict_count(self.admins) == before + 1, "a finding inside an approved exception was stored")
        covered = self.get(self.admins, f"/v1/{ORG}/rules/exceptions").json()["exceptions"]
        check(len(covered) == 1 and covered[0]["findings_covered"] == 1, f"the exception did not count the finding it covered: {covered}")
        send_line("exception-demo", "debug exception demo breach candidate aadhaar " + AADHAAR)
        check(self.verdict_count(self.admins) > before + 1, "an exception suppressed a possible breach candidate")
        newest = max((v for v in self.get(self.admins, f"/api/{ORG}/verdicts", params={"source_system": "exception-demo"}).json()["verdicts"]
                      if v["rule_id"] == "EXPOSURE_001"), key=lambda v: v["violation_id"])
        why = self.get(self.admins, f"/v1/{ORG}/findings/{newest['violation_id']}/why").json()
        check(why["recorded"] and why["trace"]["clauses"] and all("detail" in c or c["matched"] for c in why["trace"]["clauses"]) and "counsel" in why["note"], f"why: {why}")
        check(why["trace"]["exception"] and why["trace"]["exception"]["applied"] is False, "the trace does not explain that the exception did not apply")
        check(not any(raw in json.dumps(why) for raw in RAW), "the trace holds a raw value")

        def masked():
            for a in self.get(self.admins, f"/agents?org_id={ORG}").json()["agents"]:
                red = (a.get("health") or {}).get("redaction") or {}
                if a.get("source_label") == "agent-monitor" and (red.get("categories") or {}).get("phone") == "mask":
                    return True
            return False
        wait_for(masked, "the monitoring agent to take the server's redaction floor at its next heartbeat", timeout=120, interval=3)
        print("    the monitoring agent now masks phone numbers because an approved rule asked it to")
        check(self.get(self.admins, f"/api/{ORG}/verify-chain").json()["valid"], "the chain is not valid after rule changes")
        print("    overlays and an exception were approved by a second person, one review task opened, the exception counted and spared a breach candidate")

        step("audit pack, breach pack, pipeline gate, policy packs: what an auditor, a DPO and a developer each get")
        import io
        import zipfile
        pack = zipfile.ZipFile(io.BytesIO(self.get(self.admins, f"/v1/{ORG}/audit-pack").content))
        check({"evidence.jsonl", "checkpoints.jsonl", "veritas.pub", "SUMMARY.md", "VERIFY.md", "verify.sh", "MANIFEST.sha256"} <= set(pack.namelist()),
              f"the audit pack is missing files: {pack.namelist()}")
        pdir = self.work / "audit-pack"
        pack.extractall(pdir)
        shutil.copyfile(self.verifier(), pdir / ("veritas-verify.exe" if os.name == "nt" else "veritas-verify"))
        os.chmod(pdir / ("veritas-verify.exe" if os.name == "nt" else "veritas-verify"), 0o755)
        cmd = [str(pdir / ("veritas-verify.exe" if os.name == "nt" else "veritas-verify")), "--evidence", str(pdir / "evidence.jsonl"),
               "--checkpoints", str(pdir / "checkpoints.jsonl"), "--pubkey", str(pdir / "veritas.pub")]
        r = subprocess.run(cmd, capture_output=True, text=True)
        check(r.returncode == 0, f"the verifier rejected the audit pack: {r.stdout} {r.stderr}")
        if os.name != "nt":
            r = subprocess.run(["sh", str(pdir / "verify.sh")], capture_output=True, text=True)
            check(r.returncode == 0 and "PASS" in r.stdout, f"the pack's own verify.sh failed: {r.stdout} {r.stderr}")
        text = (pdir / "SUMMARY.md").read_text()
        check("does not prove" in text and not any(raw in text for raw in RAW), "the audit pack summary is wrong or holds a raw value")
        bad = pdir / "evidence-edited.jsonl"
        lines = (pdir / "evidence.jsonl").read_text().splitlines(True)
        lines[len(lines) // 2] = lines[len(lines) // 2].replace("a", "b", 1)
        bad.write_text("".join(lines))
        r = subprocess.run([cmd[0], "--evidence", str(bad), "--checkpoints", cmd[4], "--pubkey", cmd[6]], capture_output=True, text=True)
        check(r.returncode != 0, "the verifier accepted an edited audit pack")
        print("    the audit pack verifies on its own with the stand-alone verifier, and an edited copy does not")

        incidents = self.get(self.admins, f"/v1/{ORG}/incidents").json()["incidents"]
        bp = zipfile.ZipFile(io.BytesIO(self.get(self.admins, f"/v1/{ORG}/incidents/{incidents[0]['incident_id']}/breach-pack").content))
        report = bp.read("REPORT.md").decode()
        check("Not a filing and not legal advice" in report and not any(raw in report for raw in RAW), "the breach report is wrong or holds a raw value")
        print("    a draft breach report is built from the chain, with blanks for the DPO and no raw value")

        policy = self.get(self.admins, f"/v1/orgs/{ORG}/config").json()
        mig = self.work / "migrations"
        mig.mkdir()
        (self.work / "policy.json").write_text(json.dumps(policy))
        gate = [sys.executable, str(ROOT / "veritas-sdk" / "python" / "veritas_gate.py"), "--migrations", str(mig), "--policy", str(self.work / "policy.json")]
        (mig / "001.sql").write_text("CREATE TABLE audit (id int, created_at timestamp);")
        check(subprocess.run(gate, capture_output=True).returncode == 0, "the gate failed a harmless migration")
        (mig / "002.sql").write_text("ALTER TABLE audit ADD COLUMN passport_number text;")
        r = subprocess.run(gate, capture_output=True, text=True)
        check(r.returncode == 1 and "passport" in r.stdout, f"the gate let an undeclared personal-data column through: {r.stdout}")
        print("    the pipeline gate fails a migration that adds an undeclared personal-data column and passes a harmless one")

        before = self.get(self.admins, f"/v1/orgs/{ORG}/config").json()
        packs = self.get(self.admins, "/v1/policy-packs").json()["packs"]
        check({p["id"] for p in packs} == {"fintech", "healthtech", "ecommerce"}, "the policy packs are missing")
        pv = self.post(self.admins, f"/v1/{ORG}/policy-packs/ecommerce/preview", json={}).json()
        check(pv["unreviewed"] and pv["added"] and not pv["errors"], "the pack preview is wrong")
        check(self.get(self.admins, f"/v1/orgs/{ORG}/config").json() == before, "a preview changed the policy")
        check(self.post(self.admins, f"/v1/{ORG}/policy-packs/ecommerce/apply", expect=(409,), json={}).status_code == 409,
              "an unreviewed pack was applied without the acknowledgement")
        print("    a policy pack previews what it would add, saves nothing, and will not apply unreviewed without being told")

        step("tamper (F1): the server is stopped, one verdict is edited with every later hash recomputed, another organization loses its tail")
        self.stop_server()
        for a in self.agents:
            a.terminate()
        sys.path.insert(0, str(SERVER_DIR))
        os.environ["VERITAS_DATA_DIR"] = str(self.data)
        from anchoring import export as anchor_export
        from anchoring.test_verifier import recompute_from
        from evidence_store.store import EvidenceStore
        store = EvidenceStore(self.data / "evidence.db")
        try:
            first_verdict = store._conn.execute("SELECT seq FROM evidence WHERE tenant_id = ? AND record_type = 'VERDICT' ORDER BY seq LIMIT 1 OFFSET 5",
                                                (ORG,)).fetchone()["seq"]
            recompute_from(store, ORG, first_verdict, edit=lambda body: body.update(severity="LOW"))
            check(store.verify_chain(ORG)["valid"] is True, "the dashboard's own check should pass after a recomputed edit (that is the point)")
            last = store._conn.execute("SELECT MAX(seq) AS m FROM evidence WHERE tenant_id = ?", (OTHER,)).fetchone()["m"]
            store._conn.execute("DELETE FROM evidence WHERE tenant_id = ? AND seq > ?", (OTHER, last - 3))
            store._conn.commit()
            for org in (ORG, OTHER):
                (self.exports[org] / "evidence.jsonl").write_text("".join(anchor_export.evidence_lines(store, org)), encoding="utf-8")
        finally:
            store.close()
        code, out = self.verify(v, self.exports[ORG])
        check(code == 1 and "CHECKPOINT_HEAD_MISMATCH" in codes(out), f"the edit was not caught: {code} {out}")
        code, out = self.verify(v, self.exports[OTHER])
        check(code == 1 and "TAIL_TRUNCATED" in codes(out), f"the truncation was not caught: {code} {out}")
        code, out = self.verify(v, self.exports[ORG], witness=self.w1)
        check(code == 1 and "CHECKPOINT_HEAD_MISMATCH" in codes(out), "the witness copies did not expose the edit")
        print("    the dashboard's check passes; the stand-alone verifier fails and names the record, with no server and no network")

        step("upgrade: a database from the previous release migrates, verifies, accepts new records and verifies again")
        self.upgrade_check()
        print("\nAll steps passed.")

    def verifier(self):
        if self.a.verifier:
            return self.a.verifier
        out = self.work / ("veritas-verify.exe" if os.name == "nt" else "veritas-verify")
        subprocess.run(["go", "build", "-o", str(out), "."], cwd=ROOT / "tools" / "veritas-verify", check=True)
        return str(out)

    def verify(self, binary, d, witness=None):
        args = [binary, "--evidence", str(d / "evidence.jsonl"), "--checkpoints", str(d / "cps.jsonl"), "--pubkey", str(d / "veritas.pub"), "--json"]
        if witness:
            args += ["--witness-dir", str(witness)]
        p = subprocess.run(args, capture_output=True, text=True)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            return p.returncode, {"stdout": p.stdout, "stderr": p.stderr}

    def upgrade_check(self):
        legacy = ROOT / "dpdpa-agent" / "evidence_store" / "evidence.db"
        check(legacy.exists(), "the legacy database fixture is missing")
        up = self.work / "upgrade"
        (up / "data").mkdir(parents=True)
        shutil.copy(legacy, up / "data" / "evidence.db")
        code = (f"import sys, os; sys.path.insert(0, {str(SERVER_DIR)!r})\n"
                "from evidence_store.store import EvidenceStore\nfrom evidence_store.test_evidence_store import _make_explained_verdict\n"
                f"s = EvidenceStore({str(up / 'data' / 'evidence.db')!r})\n"
                "tenants = s.tenants(); assert tenants, 'no tenants in the legacy database'\n"
                "before = {t: s.verify_chain(t) for t in tenants}\n"
                "assert all(v['valid'] for v in before.values()), before\n"
                "t = tenants[0]; n = s.count(t); s.append(_make_explained_verdict(tenant_id=t))\n"
                "assert s.count(t) == n + 1 and s.verify_chain(t)['valid']\n"
                "grouped = sum(s.backfill_incidents(x) for x in tenants)\n"
                "assert all(s.verify_chain(x)['valid'] for x in tenants)\n"
                "print('tenants', len(tenants), 'records', sum(s.count(x) for x in tenants), 'grouped', grouped)\n")
        env = {**os.environ, "VERITAS_DATA_DIR": str(up / "data")}
        r = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, cwd=SERVER_DIR)
        check(r.returncode == 0, f"the upgrade check failed: {r.stdout} {r.stderr}")
        print("   ", r.stdout.strip())

    def cleanup(self):
        for a in self.agents:
            if a.poll() is None:
                a.terminate()
        self.stop_server()


def codes(out):
    return {f["code"] for f in out.get("findings", [])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", default=str(Path(tempfile.gettempdir()) / "veritas-trust-e2e"))
    ap.add_argument("--verifier", default="")
    ap.add_argument("--noise", type=int, default=6000)
    ap.add_argument("--server-cmd", default=f"{shlex.quote(sys.executable)} -m uvicorn dashboard.server:app --host 127.0.0.1 --port {{port}}")
    a = ap.parse_args()
    e2e = E2E(a)
    try:
        e2e.run()
        return 0
    except Failure as f:
        print(f"\nFAILED: {f}", file=sys.stderr)
        for name in ("server.log", "agent-redact.out", "agent-monitor.out"):
            p = e2e.work / name
            if p.exists():
                print(f"--- tail of {name}", file=sys.stderr)
                print("".join(p.read_text(errors="replace").splitlines(True)[-40:]), file=sys.stderr)
        return 1
    finally:
        e2e.cleanup()


if __name__ == "__main__":
    sys.exit(main())
