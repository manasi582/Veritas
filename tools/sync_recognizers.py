#!/usr/bin/env python3
"""Copy the canonical recognizer pack (dpdpa-agent/veritas_recognizers.py) to the agent. A test fails if they differ."""
import shutil
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for dest in ("veritas-agent", "veritas-sdk/python"):
    shutil.copyfile(root / "dpdpa-agent" / "veritas_recognizers.py", root / dest / "veritas_recognizers.py")
    print(dest + "/veritas_recognizers.py updated")
