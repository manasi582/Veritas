#!/usr/bin/env python3
"""
Veritas payload gate for pipelines: fails a build when an API description or sample payload contains personal data.

    python veritas_gate.py openapi.json [more.json ...] [--allow phone,email] [--json]
    python veritas_gate.py --payloads tests/fixtures/payloads/

It reads the `example`, `examples` and `default` values of an OpenAPI document (JSON, or YAML if PyYAML is installed) and
any JSON files given, finds Aadhaar, PAN, phone, e-mail and card numbers with the same rules the server and agent use,
and exits 1 if it finds any (0 if none, 2 if it could not read something). Values are shown masked, never as written.
It needs no server and no network. It does not find names.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import veritas_recognizers as vr

EXAMPLE_KEYS = ("example", "examples", "default", "enum")


def load(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        import yaml
        return yaml.safe_load(text)
    return json.loads(text)


def leaves(node: Any, where: str, in_example: bool, out: List[Tuple[str, str]], depth: int = 0) -> None:
    if depth > 40:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            here = f"{where}/{k}"
            leaves(v, here, in_example or str(k) in EXAMPLE_KEYS, out, depth + 1)
    elif isinstance(node, list):
        for i, v in enumerate(node[:500]):
            leaves(v, f"{where}[{i}]", in_example, out, depth + 1)
    elif in_example and isinstance(node, (str, int, float)) and not isinstance(node, bool):
        out.append((where, str(node)))


def scan_document(doc: Any, label: str, whole_file: bool = False) -> List[dict]:
    found: List[dict] = []
    pairs: List[Tuple[str, str]] = []
    leaves(doc, label, whole_file, pairs)
    for where, value in pairs:
        for d in vr.scan(value[:4000]):
            found.append({"where": where, "kind": d.label.lower(), "masked": vr.mask(value[:4000], [d])[:120]})
    return found


def main(argv: Iterable[str] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("documents", nargs="*", help="OpenAPI documents (JSON or YAML)")
    ap.add_argument("--payloads", action="append", default=[], help="a folder of sample JSON payloads, or a JSON file")
    ap.add_argument("--allow", default="", help="kinds that are allowed to appear, comma separated (for example email)")
    ap.add_argument("--json", action="store_true", help="print the findings as JSON")
    a = ap.parse_args(list(argv) if argv is not None else None)
    allowed = {k.strip().lower() for k in a.allow.split(",") if k.strip()}
    findings: List[dict] = []
    problems: List[str] = []
    for doc in a.documents:
        try:
            findings += scan_document(load(Path(doc)), doc)
        except Exception as e:
            problems.append(f"{doc}: {type(e).__name__}: {e}")
    for item in a.payloads:
        p = Path(item)
        for f in sorted(p.rglob("*.json")) if p.is_dir() else [p]:
            try:
                findings += scan_document(load(f), str(f), whole_file=True)
            except Exception as e:
                problems.append(f"{f}: {type(e).__name__}: {e}")
    findings = [f for f in findings if f["kind"] not in allowed]
    if a.json:
        print(json.dumps({"findings": findings, "problems": problems}, indent=1))
    else:
        for f in findings:
            print(f"FOUND {f['kind']:8} at {f['where']}: {f['masked']}")
        for p in problems:
            print(f"COULD NOT READ {p}", file=sys.stderr)
        print(f"{len(findings)} personal-data value(s) found" + (f", {len(problems)} file(s) unreadable" if problems else ""))
    return 2 if problems and not findings else (1 if findings else 0)


if __name__ == "__main__":
    sys.exit(main())
