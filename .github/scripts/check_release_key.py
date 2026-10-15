#!/usr/bin/env python3
"""Release builds must trust the production license key and nothing else. Run before building."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BLOCK = re.compile(r"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", re.S)
production = (ROOT / "tools" / "public_key.pem").read_text().strip()
ci = (ROOT / ".github" / "ci-license-public-key.pem").read_text().strip()
bad = False
if production == ci:
    print("the CI test key is the production key"); bad = True
for rel in ("dpdpa-agent/license.py", "veritas-launcher/license.go"):
    keys = BLOCK.findall((ROOT / rel).read_text())
    if keys != [production]:
        print(f"{rel}: does not embed exactly the production key"); bad = True
    else:
        print(f"{rel}: production key")
sys.exit(1 if bad else 0)
