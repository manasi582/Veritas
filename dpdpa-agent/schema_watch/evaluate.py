"""
Compares the column changes in a database schema statement with the organization's policy and returns findings.

A change that adds a column whose name suggests personal data is:
  declared by name       the policy lists a field with that column's name (or table.column) for this system: quiet
  declared by category   the policy declares that kind of data for this system, under another field name: quiet, shown
  undeclared             the policy does not declare that kind of data for this system: a PURPOSE_001 finding

Every classified change, declared or not, is counted per system, and the kind of data is recorded for the data map. The
statement text is never stored: only table, column, action, kind and counts.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from schema_watch import classify, parser
from schemas.models import RemediationStatus, RuleId, Severity, Verdict

HIGH_KINDS = {"aadhaar", "pan", "card", "passport", "voter"}
_DDL_WORDS = re.compile(r"\b(?:CREATE|ALTER|DROP)\s+TABLE\b", re.I)
_TOKENS = re.compile(r"[a-z0-9]+")


def create_tables(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_changes (
            org TEXT NOT NULL, source_system TEXT NOT NULL, table_name TEXT NOT NULL, column_name TEXT NOT NULL,
            action TEXT NOT NULL, category TEXT NOT NULL, status TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            PRIMARY KEY (org, source_system, table_name, column_name, action))""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_stats (
            org TEXT NOT NULL, source_system TEXT NOT NULL, unrecognised INTEGER NOT NULL DEFAULT 0, statements INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (org, source_system))""")


def _declared(cfg, system: str, table: str, column: str, category: str) -> str:
    fields = [f for f in cfg.fields if f.source_system == system]
    names = {f.field_name.lower() for f in fields}
    if column.lower() in names or f"{table}.{column}".lower() in names:
        return "declared by name"
    for f in fields:
        words = set(_TOKENS.findall(f.pii_category.lower())) | set(_TOKENS.findall(f.field_name.lower()))
        if category == f.pii_category.lower() or category in words:
            return "declared by category"
    return "undeclared"


def evaluate(store, org: str, event, cfg) -> List[Verdict]:
    """Findings for one schema event (and its counters written). `cfg` is the organization's OrgConfig."""
    text = event.raw_snippet
    changes = parser.parse(text)
    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    system = event.source_system
    hints = dict(getattr(cfg, "schema_hints", None) or {})
    verdicts: List[Verdict] = []
    rows = []
    for ch in changes:
        if ch.action == parser.DROP_TABLE:
            rows.append((ch.table, "*", ch.action, "-", "dropped"))
            continue
        column = ch.new_name if ch.action == parser.RENAME and ch.new_name else ch.column
        category = classify.category_of(column, hints)
        if category is None:
            continue
        if ch.action == parser.DROP:
            rows.append((ch.table, column, ch.action, category, "dropped"))
            continue
        status = _declared(cfg, system, ch.table, column, category)
        rows.append((ch.table, column, ch.action, category, status))
        store.flows.record(org, system, [(f"{ch.table}.{column}", category)], source_kind="schema", at=now)
        if status == "undeclared" and ch.action in (parser.ADD, parser.RENAME):
            verdicts.append(Verdict(
                tenant_id=org, verdict_id=str(uuid.uuid4()), event_id=str(event.event_id), rule_id=RuleId.PURPOSE_001,
                severity=Severity.HIGH if category in HIGH_KINDS else Severity.MEDIUM, source=event.source_type,
                source_system=system, field=f"{ch.table}.{column}", timestamp=now,
                matched_registry_entry={"schema_change": f"{ch.action} {ch.table}.{column}", "category": category},
                breach_notification_candidate=False, remediation_status=RemediationStatus.OPEN, remediation_updated_at=None))
    unrecognised = 0 if changes or not _DDL_WORDS.search(text) else 1
    with store.writer() as conn:
        for table, column, action, category, status in rows:
            conn.execute("""
                INSERT INTO schema_changes (org, source_system, table_name, column_name, action, category, status, count, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(org, source_system, table_name, column_name, action) DO UPDATE SET
                    count = count + 1, last_seen = excluded.last_seen, category = excluded.category, status = excluded.status""",
                         (org, system, table, column, action, category, status, stamp, stamp))
        conn.execute("""INSERT INTO schema_stats (org, source_system, unrecognised, statements) VALUES (?, ?, ?, 1)
                        ON CONFLICT(org, source_system) DO UPDATE SET unrecognised = unrecognised + ?, statements = statements + 1""",
                     (org, system, unrecognised, unrecognised))
    return verdicts


def listing(store, org: str, limit: int = 200) -> dict:
    with store._lock:
        c = store._conn
        rows = [dict(r) for r in c.execute(
            "SELECT source_system, table_name, column_name, action, category, status, count, first_seen, last_seen "
            "FROM schema_changes WHERE org = ? ORDER BY last_seen DESC LIMIT ?", (org, max(1, min(limit, 1000))))]
        stats = [dict(r) for r in c.execute("SELECT source_system, unrecognised, statements FROM schema_stats WHERE org = ? "
                                            "ORDER BY source_system", (org,))]
    return {"changes": rows, "systems": stats,
            "note": "Veritas reads the structure of database changes, not the data. A name suggests, it does not prove, that a column holds personal data."}
