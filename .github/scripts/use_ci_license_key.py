#!/usr/bin/env python3
"""
Test builds only: make the server and the Windows launcher in THIS checkout trust the CI test
license key instead of the production key, so CI never needs the production private key.

It rewrites the embedded public key in dpdpa-agent/license.py and veritas-launcher/license.go.
Never run it in a release build: the release workflow checks that the production key is in place.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI_KEY = (ROOT / ".github" / "ci-license-public-key.pem").read_text().strip()
BLOCK = re.compile(r"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", re.S)

for rel in ("dpdpa-agent/license.py", "veritas-launcher/license.go"):
    path = ROOT / rel
    text = path.read_text()
    if len(BLOCK.findall(text)) != 1:
        sys.exit(f"{rel}: expected exactly one embedded public key")
    path.write_text(BLOCK.sub(lambda _: CI_KEY, text, count=1))
    print(f"{rel}: now trusts the CI test key")
