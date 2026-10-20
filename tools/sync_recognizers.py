#!/usr/bin/env python3
"""Copy the canonical recognizer pack (dpdpa-agent/veritas_recognizers.py) to the agent and the SDK, and the DDL parser and
column classifier (dpdpa-agent/schema_watch/) to the SDK for the pipeline gate. A test fails if the copies differ."""
import shutil
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for dest in ("veritas-agent", "veritas-sdk/python"):
    shutil.copyfile(root / "dpdpa-agent" / "veritas_recognizers.py", root / dest / "veritas_recognizers.py")
    print(dest + "/veritas_recognizers.py updated")
for src, name in (("parser.py", "veritas_ddl_parser.py"), ("classify.py", "veritas_ddl_classify.py")):
    shutil.copyfile(root / "dpdpa-agent" / "schema_watch" / src, root / "veritas-sdk" / "python" / name)
    print("veritas-sdk/python/" + name + " updated")
