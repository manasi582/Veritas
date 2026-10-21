#!/usr/bin/env python3
"""
Veritas payload gate for pipelines: fails a build when an API description or sample payload contains personal data.

    python veritas_gate.py openapi.json [more.json ...] [--allow phone,email] [--json]
    python veritas_gate.py --payloads tests/fixtures/payloads/
    python veritas_gate.py --migrations db/migrations/ --policy veritas-policy.yaml [--system orders-db]

It reads the `example`, `examples` and `default` values of an OpenAPI document (JSON, or YAML if PyYAML is installed) and
any JSON files given, finds Aadhaar, PAN, phone, e-mail and card numbers with the same rules the server and agent use,
and exits 1 if it finds any (0 if none, 2 if it could not read something). Values are shown masked, never as written.
With --migrations it reads SQL migration files (PostgreSQL and MySQL), works out which columns they leave in place, and fails the
build for each column whose name suggests personal data (phone, email, aadhaar, PAN, card, name, date of birth, address and so on)
that the policy does not declare. A column added and later dropped does not count. `schema_hints` in the policy corrects a wrong
guess (a column name or pattern mapped to a kind, or to "none").
It needs no server and no network. It does not find names in payloads, and it guesses a column's kind from its name only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import veritas_ddl_classify as classify
import veritas_ddl_parser as ddl
import veritas_recognizers as vr

_WORDS = re.compile(r"[a-z0-9]+")

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


# Documentation placeholders are not personal data: an e-mail at a domain reserved for examples (RFC 2606) or testing.
_RESERVED_DOMAINS = ("example.com", "example.org", "example.net", "example.edu")
_RESERVED_TLDS = (".example", ".test", ".invalid", ".localhost")


def is_placeholder_email(text: str) -> bool:
    domain = text.rsplit("@", 1)[-1].strip().lower().rstrip(".>) ,;")
    return domain in _RESERVED_DOMAINS or domain.endswith(tuple("." + d for d in _RESERVED_DOMAINS)) or domain.endswith(_RESERVED_TLDS)


def scan_document(doc: Any, label: str, whole_file: bool = False) -> List[dict]:
    found: List[dict] = []
    pairs: List[Tuple[str, str]] = []
    leaves(doc, label, whole_file, pairs)
    for where, value in pairs:
        for d in vr.scan(value[:4000]):
            if d.label.lower() == "email" and is_placeholder_email(value[:4000][d.start:d.end]):
                continue
            found.append({"where": where, "kind": d.label.lower(), "masked": vr.mask(value[:4000], [d])[:120]})
    return found


def load_policy(path: Path) -> dict:
    doc = load(path)
    if not isinstance(doc, dict) or not isinstance(doc.get("fields", []), list):
        raise ValueError("a policy file is an object with a list called `fields`")
    return doc


def declared_how(policy: dict, system: Optional[str], table: str, column: str, category: str) -> str:
    """The same test the server applies to a schema change (dpdpa-agent/schema_watch/evaluate.py)."""
    fields = [f for f in policy.get("fields", []) if system is None or f.get("source_system") == system]
    names = {str(f.get("field_name", "")).lower() for f in fields}
    if column.lower() in names or f"{table}.{column}".lower() in names:
        return "declared by name"
    for f in fields:
        words = set(_WORDS.findall(str(f.get("pii_category", "")).lower())) | set(_WORDS.findall(str(f.get("field_name", "")).lower()))
        if category == str(f.get("pii_category", "")).lower() or category in words:
            return "declared by category"
    return "undeclared"


def columns_left_by(files: List[Path], hints: dict) -> Tuple[Dict[Tuple[str, str], Tuple[str, str]], int]:
    """Apply the files in name order; return {(table, column): (kind, file)} still present, and how many files held no DDL."""
    state: Dict[Tuple[str, str], Tuple[str, str]] = {}
    empty = 0
    for f in files:
        changes = ddl.parse(f.read_text(encoding="utf-8", errors="replace"))
        if not changes:
            empty += 1
        for ch in changes:
            t = ch.table.lower()
            if ch.action == ddl.DROP_TABLE:
                state = {k: v for k, v in state.items() if k[0] != t}
            elif ch.action == ddl.DROP:
                state.pop((t, (ch.column or "").lower()), None)
            elif ch.action == ddl.RENAME and ch.new_name:
                old = state.pop((t, (ch.column or "").lower()), None)
                kind = classify.category_of(ch.new_name, hints)
                if kind:
                    state[(t, ch.new_name.lower())] = (kind, str(f))
                elif old:
                    pass
            elif ch.action == ddl.ADD and ch.column:
                kind = classify.category_of(ch.column, hints)
                if kind:
                    state[(t, ch.column.lower())] = (kind, str(f))
    return state, empty


def scan_migrations(paths: List[str], policy: dict, system: Optional[str]) -> Tuple[List[dict], List[str]]:
    files: List[Path] = []
    problems: List[str] = []
    for item in paths:
        p = Path(item)
        if p.is_dir():
            files += sorted(x for x in p.rglob("*") if x.suffix.lower() in (".sql", ".ddl"))
        elif p.is_file():
            files.append(p)
        else:
            problems.append(f"{item}: not found")
    files = sorted(dict.fromkeys(files), key=lambda x: str(x))
    if not files and not problems:
        problems.append("no .sql files found in " + ", ".join(paths))
    state, _ = columns_left_by(files, dict(policy.get("schema_hints") or {}))
    findings = []
    for (table, column), (kind, where) in sorted(state.items()):
        if declared_how(policy, system, table, column, kind) == "undeclared":
            findings.append({"where": where, "kind": kind, "table": table, "column": column,
                             "message": f"{table}.{column} looks like {kind} data and the policy does not declare it"})
    return findings, problems


def main(argv: Iterable[str] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("documents", nargs="*", help="OpenAPI documents (JSON or YAML)")
    ap.add_argument("--payloads", action="append", default=[], help="a folder of sample JSON payloads, or a JSON file")
    ap.add_argument("--allow", default="", help="kinds that are allowed to appear, comma separated (for example email)")
    ap.add_argument("--migrations", action="append", default=[], help="a folder of SQL migrations, or a SQL file (needs --policy)")
    ap.add_argument("--policy", help="the organization's policy file (YAML or JSON) listing the declared fields")
    ap.add_argument("--system", help="only fields declared for this source system count (default: any system)")
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
    if a.migrations:
        if not a.policy:
            print("--migrations needs --policy", file=sys.stderr)
            return 2
        try:
            policy = load_policy(Path(a.policy))
        except Exception as e:
            print(f"COULD NOT READ {a.policy}: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
        undeclared, issues = scan_migrations(a.migrations, policy, a.system)
        findings += [f for f in undeclared if f["kind"] not in allowed]
        problems += issues
    if a.json:
        print(json.dumps({"findings": findings, "problems": problems}, indent=1))
    else:
        for f in findings:
            print(f"FOUND {f['kind']:8} at {f['where']}: {f['masked']}" if "masked" in f else f"UNDECLARED {f['kind']:8} {f['message']} (in {f['where']})")
        for p in problems:
            print(f"COULD NOT READ {p}", file=sys.stderr)
        values = [f for f in findings if "masked" in f]
        columns = [f for f in findings if "masked" not in f]
        print(f"{len(values)} personal-data value(s) found"
              + (f", {len(columns)} undeclared personal-data column(s)" if a.migrations else "")
              + (f", {len(problems)} file(s) unreadable" if problems else ""))
    return 2 if problems and not findings else (1 if findings else 0)


if __name__ == "__main__":
    sys.exit(main())
