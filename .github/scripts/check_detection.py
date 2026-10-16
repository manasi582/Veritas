#!/usr/bin/env python3
"""
After the server was restarted with VERITAS_DETECTION_WORKERS=N: the worker processes are up and a real
event is detected by them. Exit 1 with the reason otherwise.

Environment: VERITAS_URL, VERITAS_ADMIN_USER, VERITAS_ADMIN_PASSWORD, VERITAS_ORG, EXPECT_WORKERS.
"""
import os
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()
URL = os.environ.get("VERITAS_URL", "https://localhost:8000").rstrip("/")
ORG = os.environ["VERITAS_ORG"]
WANT = int(os.environ.get("EXPECT_WORKERS", "2"))


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


s = requests.Session()
s.verify = False
r = s.post(f"{URL}/api/auth/login", data={"username": os.environ["VERITAS_ADMIN_USER"],
                                          "password": os.environ["VERITAS_ADMIN_PASSWORD"]}, timeout=30)
if r.status_code != 200:
    fail(f"sign-in failed ({r.status_code})")


def detection():
    return s.get(f"{URL}/api/system/health", timeout=30).json()["checks"]["detection"]


deadline = time.time() + 240          # every worker loads the language model: about a minute
d = detection()
while time.time() < deadline and (d.get("mode") != "pool" or d.get("ready_workers", 0) < WANT):
    time.sleep(5)
    d = detection()
if d.get("mode") != "pool" or d.get("workers") != WANT:
    fail(f"expected {WANT} detection workers, the server reports {d}")
if d.get("ready_workers", 0) < WANT:
    fail(f"only {d.get('ready_workers')} of {WANT} workers became ready: {d}")

r = s.post(f"{URL}/v1/{ORG}/scan", timeout=120,
           json={"text": "debug: customer PAN ABCDE1234F phone +91 98765 43210", "source_system": "order-service"})
if r.status_code != 200 or not r.json().get("contains_pii"):
    fail(f"an event was not detected by the workers: {r.status_code} {r.text[:200]}")
d2 = detection()
if d2["completed"] < d["completed"] + 1:
    fail(f"the worker pool did not count the event: {d2}")
print(f"detection pool ok: {d2}")
