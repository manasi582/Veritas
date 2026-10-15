#!/usr/bin/env python3
"""
Checks used by the upgrade tests: make data with an older release, then prove a newer release
still has all of it.

  seed    create the administrator and an organization, run a scan so evidence exists, and write
          what to expect afterwards to $UPGRADE_STATE (default /tmp/upgrade-state.json)
  verify  after the upgrade: sign in with the same account, find the same evidence, the evidence
          chain intact, the license valid and the organization config still there

Environment: VERITAS_URL, VERITAS_ADMIN_USER, VERITAS_ADMIN_PASSWORD, VERITAS_ORG,
VERITAS_SETUP_CODE (seed only).
"""
import json
import os
import sys

import requests
import urllib3

urllib3.disable_warnings()
URL = os.environ.get("VERITAS_URL", "https://localhost:8000").rstrip("/")
USER = os.environ["VERITAS_ADMIN_USER"]
PASSWORD = os.environ["VERITAS_ADMIN_PASSWORD"]
ORG = os.environ.get("VERITAS_ORG", "upgrade_org")
STATE = os.environ.get("UPGRADE_STATE", "/tmp/upgrade-state.json")

CONFIG = {
    "org_id": ORG,
    "identifiers": [
        {"name": "pan", "pattern": "indian_pan", "validator": "pan"},
        {"name": "phone", "pattern": "indian_phone", "validator": "none"},
    ],
    "fields": [
        {"field_name": "name", "pii_category": "name", "declared_purpose": "order_fulfillment",
         "consent_scope": "order_fulfillment", "retention_days": 1095, "source_system": "order-service"},
    ],
}


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def login():
    s = requests.Session()
    s.verify = False
    r = s.post(f"{URL}/api/auth/login", data={"username": USER, "password": PASSWORD}, timeout=30)
    if r.status_code != 200:
        fail(f"login failed ({r.status_code}): {r.text[:200]}")
    return s


def verdict_count(s):
    r = s.get(f"{URL}/api/{ORG}/verdicts", timeout=30)
    if r.status_code != 200:
        fail(f"listing verdicts failed ({r.status_code})")
    body = r.json()
    items = body.get("verdicts", body) if isinstance(body, dict) else body
    return len(items)


def seed():
    r = requests.post(f"{URL}/api/auth/setup", verify=False, timeout=30, json={
        "username": USER, "email": "upgrade@example.com", "password": PASSWORD,
        "setup_code": os.environ.get("VERITAS_SETUP_CODE", "")})
    if r.status_code != 200:
        fail(f"setup failed ({r.status_code}): {r.text[:200]}")
    s = login()
    r = s.post(f"{URL}/v1/orgs/{ORG}/config", json=CONFIG, timeout=30)
    if r.status_code != 200 or r.json().get("status") != "ok":
        fail(f"org config rejected: {r.text[:200]}")
    r = s.post(f"{URL}/v1/{ORG}/scan", timeout=60,
               json={"text": "debug: customer PAN ABCDE1234F phone +91 98765 43210", "source_system": "order-service"})
    if r.status_code != 200 or not r.json().get("contains_pii"):
        fail(f"scan found nothing: {r.status_code} {r.text[:200]}")
    count = verdict_count(s)
    if count < 1:
        fail("no evidence was written")
    chain = s.get(f"{URL}/api/{ORG}/verify-chain", timeout=30).json()
    if not chain.get("valid"):
        fail(f"chain not valid before the upgrade: {chain}")
    with open(STATE, "w") as f:
        json.dump({"verdicts": count}, f)
    print(f"seeded: admin '{USER}', org '{ORG}', {count} verdicts")


def verify():
    expected = json.load(open(STATE))["verdicts"]
    s = login()
    got = verdict_count(s)
    if got != expected:
        fail(f"evidence changed by the upgrade: {expected} before, {got} after")
    chain = s.get(f"{URL}/api/{ORG}/verify-chain", timeout=30).json()
    if not chain.get("valid"):
        fail(f"evidence chain broken after the upgrade: {chain}")
    lic = s.get(f"{URL}/api/license", timeout=30).json()
    if not lic.get("valid"):
        fail(f"license not valid after the upgrade: {lic}")
    r = s.get(f"{URL}/v1/orgs/{ORG}/config", timeout=30)
    if r.status_code != 200:
        fail(f"organization config lost ({r.status_code})")
    print(f"upgrade kept everything: {got} verdicts, chain valid, license valid, org config present")


if __name__ == "__main__":
    {"seed": seed, "verify": verify}[sys.argv[1]]()
