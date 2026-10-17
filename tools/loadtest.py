#!/usr/bin/env python3
"""
Load test: many simulated agents send events to a running Veritas server, and the result says how
fast it took them and whether anything was lost.

    python tools/loadtest.py --url https://localhost:8000 --agents 20 --duration 60

Needs an administrator (to make a test organization and one reusable agent key):
    VERITAS_ADMIN_USER / VERITAS_ADMIN_PASSWORD

What it does
  1. signs in once (the sign-in limit is 10 per 5 minutes), creates the organization `load_<time>`,
     and issues one reusable key for all simulated agents;
  2. registers --agents agents, each with its own token, like real ones;
  3. runs each agent in its own thread, sending events one after another for --duration seconds
     (or --events each), a mix of lines with personal data and lines without;
  4. checks the books: the findings the server reported in its answers == the findings it stored for the
     organization (a rejected or lost event is counted, not hidden), and the evidence chain still verifies;
  5. prints a table and writes JSON (--out) so runs can be compared.

An event is "accepted" on HTTP 200. HTTP 429 or 5xx, timeouts and refused connections are errors,
reported separately. The test never changes anything outside the organization it creates.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import threading
import time
from typing import List

import requests
import urllib3

urllib3.disable_warnings()

LINES_WITH_PII = [
    "2026-10-15 10:01:02 INFO order placed for Rahul Sharma PAN ABCDE1234F phone +91 98765 43210",
    "2026-10-15 10:01:03 DEBUG kyc payload {\"name\": \"Priya Nair\", \"aadhaar\": \"2345 6789 0123\"}",
    "2026-10-15 10:01:04 WARN failed login for amit.verma@example.com from 10.0.0.7",
]
LINES_CLEAN = [
    "2026-10-15 10:01:05 INFO health check ok latency=12ms",
    "2026-10-15 10:01:06 INFO cache refreshed 1432 keys in 88ms",
    "2026-10-15 10:01:07 INFO request GET /api/items 200 4ms",
]


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, int(round(p / 100.0 * (len(ordered) - 1)))))
    return ordered[k]


class Agent(threading.Thread):
    def __init__(self, idx, base, org, token, stop_at, events, pii_ratio):
        super().__init__(daemon=True)
        self.idx, self.base, self.org, self.token = idx, base, org, token
        self.stop_at, self.max_events, self.pii_ratio = stop_at, events, pii_ratio
        self.latencies: List[float] = []
        self.accepted = 0
        self.verdicts = 0
        self.errors: dict = {}

    def run(self):
        s = requests.Session()
        s.verify = False
        s.headers["Authorization"] = f"Bearer {self.token}"
        n = 0
        while True:
            if self.max_events is not None and n >= self.max_events:
                break
            if self.max_events is None and time.time() >= self.stop_at:
                break
            with_pii = (n % 100) < int(self.pii_ratio * 100)
            pool = LINES_WITH_PII if with_pii else LINES_CLEAN
            line = pool[(n + self.idx) % len(pool)]
            body = {"source_type": "log", "source_system": "kyc-service" if with_pii else "order-service",
                    "raw_snippet": line}
            t0 = time.perf_counter()
            try:
                r = s.post(f"{self.base}/v1/{self.org}/events", json=body, timeout=60)
                dt = time.perf_counter() - t0
                if r.status_code == 200:
                    self.accepted += 1
                    self.verdicts += len(r.json().get("verdicts", []))
                    self.latencies.append(dt)
                else:
                    self.errors[f"http_{r.status_code}"] = self.errors.get(f"http_{r.status_code}", 0) + 1
            except requests.RequestException as e:
                key = type(e).__name__
                self.errors[key] = self.errors.get(key, 0) + 1
            n += 1


def run_group(spec):
    """One load-generating process: runs its share of the agents and returns their totals."""
    base, org, first_idx, tokens, stop_at, events, pii_ratio = spec
    group = [Agent(first_idx + i, base, org, t, stop_at, events, pii_ratio) for i, t in enumerate(tokens)]
    for a in group:
        a.start()
    for a in group:
        a.join()
    errors: dict = {}
    for a in group:
        for k, v in a.errors.items():
            errors[k] = errors.get(k, 0) + v
    return ([x for a in group for x in a.latencies], sum(a.accepted for a in group),
            sum(a.verdicts for a in group), errors)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("VERITAS_URL", "https://localhost:8000"))
    ap.add_argument("--agents", type=int, default=10)
    ap.add_argument("--duration", type=float, default=30.0, help="seconds each agent sends (ignored with --events)")
    ap.add_argument("--events", type=int, default=None, help="events per agent instead of a duration")
    ap.add_argument("--pii-ratio", type=float, default=0.3, help="share of lines that hold personal data")
    ap.add_argument("--processes", type=int, default=1,
                    help="load-generating processes (one Python process cannot send more than a few hundred "
                         "requests a second; raise this when measuring a fast server)")
    ap.add_argument("--out", default=None, help="write the result as JSON to this file")
    ap.add_argument("--max-error-rate", type=float, default=0.0, help="exit 1 if more than this share of events fail")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    user, password = os.environ["VERITAS_ADMIN_USER"], os.environ["VERITAS_ADMIN_PASSWORD"]
    org = f"load_{int(time.time())}"

    admin = requests.Session()
    admin.verify = False
    r = admin.post(f"{base}/api/auth/login", data={"username": user, "password": password}, timeout=30)
    if r.status_code != 200:
        print(f"sign-in failed: {r.status_code} {r.text[:200]}", file=sys.stderr)
        return 2
    cfg = {"org_id": org,
           "identifiers": [{"name": "pan", "pattern": "indian_pan", "validator": "pan"},
                           {"name": "aadhaar", "pattern": "indian_aadhaar", "validator": "aadhaar"},
                           {"name": "phone", "pattern": "indian_phone", "validator": "none"}],
           "fields": [{"field_name": "name", "pii_category": "name", "declared_purpose": "order_fulfillment",
                       "consent_scope": "order_fulfillment", "retention_days": 1095, "source_system": "order-service"}]}
    r = admin.post(f"{base}/v1/orgs/{org}/config", json=cfg, timeout=30)
    if r.status_code != 200 or r.json().get("status") != "ok":
        print(f"organization rejected: {r.status_code} {r.text[:200]}", file=sys.stderr)
        return 2
    r = admin.post(f"{base}/agents/issue-key", json={"org_id": org, "max_uses": args.agents, "label": "loadtest"}, timeout=30)
    if r.status_code != 200:
        print(f"could not issue a key: {r.status_code} {r.text[:200]}", file=sys.stderr)
        return 2
    key = r.json()["key"]

    tokens = []
    for i in range(args.agents):
        r = requests.post(f"{base}/agent/register", verify=False, timeout=30,
                          json={"registration_key": key, "source_label": f"load-agent-{i}"})
        if r.status_code != 200:
            print(f"agent {i} could not register: {r.status_code} {r.text[:200]}", file=sys.stderr)
            return 2
        tokens.append(r.json()["auth_token"])

    print(f"organization {org}: {args.agents} agents, "
          f"{'%d events each' % args.events if args.events else '%.0f s' % args.duration}", flush=True)
    stop_at = time.time() + args.duration
    started = time.perf_counter()
    procs = max(1, min(args.processes, args.agents))
    shares = [tokens[i::procs] for i in range(procs)]
    specs = [(base, org, i, shares[i], stop_at, args.events, args.pii_ratio) for i in range(procs)]
    if procs == 1:
        groups = [run_group(specs[0])]
    else:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=procs) as ex:
            groups = list(ex.map(run_group, specs))
    elapsed = time.perf_counter() - started

    latencies = [x for g in groups for x in g[0]]
    accepted = sum(g[1] for g in groups)
    expected_findings = sum(g[2] for g in groups)
    errors: dict = {}
    for g in groups:
        for k, v in g[3].items():
            errors[k] = errors.get(k, 0) + v
    failed = sum(errors.values())
    total = accepted + failed

    # the books: what the server says it stored
    stored = None
    try:
        rows = admin.get(f"{base}/api/{org}/stats", timeout=120).json()
        stored = rows.get("total")
    except Exception:
        pass
    chain = None
    try:
        chain = admin.get(f"{base}/api/{org}/verify-chain", timeout=300).json().get("valid")
    except Exception:
        pass
    health = None
    try:
        health = admin.get(f"{base}/api/system/health", timeout=30).json().get("healthy")
    except Exception:
        pass

    result = {
        "organization": org, "agents": args.agents, "seconds": round(elapsed, 1),
        "events_sent": total, "events_accepted": accepted, "events_failed": failed, "errors": errors,
        "throughput_events_per_second": round(accepted / elapsed, 1) if elapsed else 0,
        "latency_ms": {"p50": round(1000 * percentile(latencies, 50), 1),
                       "p95": round(1000 * percentile(latencies, 95), 1),
                       "p99": round(1000 * percentile(latencies, 99), 1),
                       "max": round(1000 * max(latencies), 1) if latencies else 0,
                       "mean": round(1000 * statistics.mean(latencies), 1) if latencies else 0},
        "client_processes": procs, "client_cpus": os.cpu_count(),
        "pii_ratio": args.pii_ratio, "findings_expected": expected_findings,
        "findings_stored": stored, "evidence_chain_valid": chain, "server_healthy_after": health,
    }
    print(json.dumps(result, indent=2))
    if args.out:
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2)

    problems = []
    if total and failed / total > args.max_error_rate:
        problems.append(f"{failed} of {total} events failed")
    if stored is not None and stored != expected_findings:
        problems.append(f"the server answered with {expected_findings} findings but stored {stored}")
    if chain is False:
        problems.append("the evidence chain no longer verifies")
    if health is False:
        problems.append("the server reports itself unhealthy after the run")
    if problems:
        print("PROBLEMS: " + "; ".join(problems), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
