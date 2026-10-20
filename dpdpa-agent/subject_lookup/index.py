"""
The identifier index: which systems observed an identifier, how often and when, without keeping the identifier.

When the server sees a structured identifier (phone, e-mail, Aadhaar, PAN, card) it reduces it to a canonical form
(veritas_recognizers.normalise_identifier) and stores only HMAC-SHA256(organization lookup key, form), counted per
system. When an agent has already hashed it, the token in the text is stored as it arrived. A lookup normalises and
tokenises the identifier that was typed in, with every key that is not retired, and reads the counts back.

Counts are collected in memory and written in batches (like the data map's), except that the watch list is checked at
once, on every event. No raw identifier is ever stored; the one typed into a lookup is used in memory and dropped.
"""
from __future__ import annotations

import re
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

import veritas_recognizers as vr

CATEGORIES = ("aadhaar", "pan", "phone", "email", "card")
ENTITY_CATEGORY = {"IN_AADHAAR": "aadhaar", "IN_PAN": "pan", "IN_PHONE": "phone", "PHONE_NUMBER": "phone",
                   "EMAIL_ADDRESS": "email", "CREDIT_CARD": "card"}
FLUSH_SECONDS, FLUSH_KEYS, KEEP_VERDICTS = 5.0, 300, 10
_TOKEN = re.compile(vr.TOKEN_PATTERN)
_PLACEHOLDERISH = re.compile(r"^\[[A-Z]+(?:_REDACTED|#[0-9a-f]{6}\.[0-9a-f]{16})\]$")
_PAN = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")


def create_tables(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pii_tokens (
            org TEXT NOT NULL, key_id TEXT NOT NULL, token TEXT NOT NULL, category TEXT NOT NULL,
            source_system TEXT NOT NULL, event_count INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            PRIMARY KEY (org, key_id, token, category, source_system))""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pii_token_verdicts (
            org TEXT NOT NULL, key_id TEXT NOT NULL, token TEXT NOT NULL, verdict_id TEXT NOT NULL, seen_at TEXT NOT NULL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pii_token_verdicts ON pii_token_verdicts(org, key_id, token)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS token_watchlist (
            org TEXT NOT NULL, key_id TEXT NOT NULL, token TEXT NOT NULL, request_id TEXT NOT NULL, added_at TEXT NOT NULL,
            PRIMARY KEY (org, key_id, token, request_id))""")


class InvalidIdentifier(ValueError):
    """The text typed in does not look like the kind of identifier named. The message never repeats it."""


def clean_identifier(category: str, identifier: str) -> str:
    """The canonical form of a typed identifier, or InvalidIdentifier."""
    category = (category or "").lower()
    if category not in CATEGORIES:
        raise InvalidIdentifier("Unknown kind of identifier. Use one of: " + ", ".join(CATEGORIES) + ".")
    form = vr.normalise_identifier(category.upper(), identifier if isinstance(identifier, str) else "")
    ok = {"phone": len(form) == 10 and form[0] in "6789",
          "aadhaar": len(form) == 12 and form.isdigit() and form[0] != "0",
          "pan": bool(_PAN.match(form)),
          "email": "@" in form and "." in form.split("@")[-1] and 3 <= len(form) <= 254,
          "card": form.isdigit() and 13 <= len(form) <= 19}[category]
    if not ok:
        raise InvalidIdentifier(f"That does not look like a valid {category} identifier.")
    return form


class SubjectIndex:
    def __init__(self, store) -> None:
        self._store = store
        self._lock = threading.Lock()
        self._pending: Dict[tuple, list] = {}
        self._links: List[tuple] = []
        self._last_flush = time.monotonic()
        self._watch: Dict[str, Dict[Tuple[str, str], str]] = {}
        self._keys: Dict[str, Tuple[str, bytes]] = {}

    # ---- keys and the watch list (cached) ------------------------------------------------------------

    def forget_keys(self, org: Optional[str] = None) -> None:
        with self._lock:
            if org is None:
                self._keys.clear()
            else:
                self._keys.pop(org, None)

    def _lookup_key(self, org: str) -> Tuple[str, bytes]:
        with self._lock:
            hit = self._keys.get(org)
        if hit is None:
            hit = self._store.keyring.current(org, "lookup")
            with self._lock:
                self._keys[org] = hit
        return hit

    def watched(self, org: str) -> Dict[Tuple[str, str], str]:
        with self._lock:
            cached = self._watch.get(org)
        if cached is None:
            with self._store._lock:
                rows = self._store._conn.execute(
                    "SELECT key_id, token, request_id FROM token_watchlist WHERE org = ? ORDER BY added_at", (org,)).fetchall()
            cached = {(r["key_id"], r["token"]): r["request_id"] for r in rows}
            with self._lock:
                self._watch[org] = cached
        return cached

    def forget_watch(self, org: str) -> None:
        with self._lock:
            self._watch.pop(org, None)

    # ---- tokens for an event --------------------------------------------------------------------------

    def tokens_for_event(self, org: str, matches: Iterable, raw_snippet: str = "") -> List[Tuple[str, str, str]]:
        """(key_id, token, category) for each structured identifier found in or reported about one event."""
        out = set()
        kid = key = None
        for m in matches:
            category = ENTITY_CATEGORY.get(m.entity_type)
            value = m.matched_text or ""
            if not category or m.validation_status == "failed_validation" or _PLACEHOLDERISH.match(value):
                continue
            form = vr.normalise_identifier(category.upper(), value)
            if not form or (category == "phone" and len(form) != 10):
                continue
            if key is None:
                kid, key = self._lookup_key(org)
            out.add((kid, vr.keyed_digest(category.upper(), value, key), category))
        for m in _TOKEN.finditer(raw_snippet or ""):          # an agent already hashed these
            out.add((m.group(2), m.group(3), m.group(1).lower()))
        return sorted(out)

    def watch_hits(self, org: str, tokens: List[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
        """[(key_id, token, request_id)] for tokens on the watch list. Checked at once, on every event."""
        if not tokens:
            return []
        watch = self.watched(org)
        return sorted({(k, t, watch[(k, t)]) for k, t, _ in tokens if (k, t) in watch})

    # ---- recording ------------------------------------------------------------------------------------

    def record(self, org: str, system: str, tokens: List[Tuple[str, str, str]], verdict_ids: Iterable[str] = (),
               at: Optional[datetime] = None) -> List[Tuple[str, str, str]]:
        """Count one event. Returns [(key_id, token, request_id)] for tokens on the watch list (checked at once)."""
        if not tokens:
            return []
        stamp = (at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
        watch = self.watched(org)
        hits = [(k, t, watch[(k, t)]) for k, t, _ in tokens if (k, t) in watch]
        verdict_ids = list(verdict_ids)
        with self._lock:
            for kid, token, category in tokens:
                slot = self._pending.setdefault((org, kid, token, category, system), [0, stamp, stamp])
                slot[0] += 1
                slot[2] = stamp
                for vid in verdict_ids:
                    self._links.append((org, kid, token, vid, stamp))
            due = len(self._pending) >= FLUSH_KEYS or time.monotonic() - self._last_flush >= FLUSH_SECONDS
        if due:
            try:
                self.flush()
            except Exception:
                pass
        return hits

    def flush(self) -> int:
        with self._lock:
            batch, links = self._pending, self._links
            self._pending, self._links = {}, []
            self._last_flush = time.monotonic()
        if not batch and not links:
            return 0
        try:
            with self._store.writer() as conn:
                for (org, kid, token, category, system), (n, first, last) in batch.items():
                    conn.execute("""
                        INSERT INTO pii_tokens (org, key_id, token, category, source_system, event_count, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(org, key_id, token, category, source_system) DO UPDATE SET
                            event_count = event_count + excluded.event_count,
                            first_seen = MIN(first_seen, excluded.first_seen),
                            last_seen = MAX(last_seen, excluded.last_seen)""",
                                 (org, kid, token, category, system, n, first, last))
                touched = set()
                for org, kid, token, vid, stamp in links:
                    conn.execute("INSERT INTO pii_token_verdicts (org, key_id, token, verdict_id, seen_at) VALUES (?, ?, ?, ?, ?)",
                                 (org, kid, token, vid, stamp))
                    touched.add((org, kid, token))
                for org, kid, token in touched:        # keep the latest few per token
                    conn.execute("""DELETE FROM pii_token_verdicts WHERE rowid IN (
                                      SELECT rowid FROM pii_token_verdicts WHERE org = ? AND key_id = ? AND token = ?
                                      ORDER BY seen_at DESC, rowid DESC LIMIT -1 OFFSET ?)""", (org, kid, token, KEEP_VERDICTS))
        except Exception:
            with self._lock:
                for key, (n, first, last) in batch.items():
                    slot = self._pending.setdefault(key, [0, first, last])
                    slot[0] += n
                    slot[1], slot[2] = min(slot[1], first), max(slot[2], last)
                self._links = links + self._links
            raise
        return len(batch)

    # ---- lookup ---------------------------------------------------------------------------------------

    def tokens_for_identifier(self, org: str, category: str, identifier: str) -> List[Tuple[str, str]]:
        """Every (key_id, token) this identifier has under the organization's active keys (raises InvalidIdentifier)."""
        form = clean_identifier(category, identifier)
        label = category.upper()
        out = []
        for kid, key in self._store.keyring.active(org, "lookup"):
            out.append((kid, vr.keyed_digest(label, form, key)))
        for kid, key in self._store.keyring.active(org, "agent"):
            out.append((kid, vr.keyed_digest(label, form, key)[:16]))
        return out

    def lookup_tokens(self, org: str, category: str, pairs: List[Tuple[str, str]]) -> dict:
        self.flush()
        category = category.lower()
        systems: Dict[str, dict] = {}
        verdicts: List[dict] = []
        with self._store._lock:
            c = self._store._conn
            for kid, token in pairs:
                for r in c.execute("SELECT source_system, event_count, first_seen, last_seen FROM pii_tokens "
                                   "WHERE org = ? AND key_id = ? AND token = ? AND category = ?", (org, kid, token, category)):
                    s = systems.setdefault(r["source_system"], {"system": r["source_system"], "events": 0,
                                                                "first_seen": r["first_seen"], "last_seen": r["last_seen"]})
                    s["events"] += r["event_count"]
                    s["first_seen"], s["last_seen"] = min(s["first_seen"], r["first_seen"]), max(s["last_seen"], r["last_seen"])
                for r in c.execute("""SELECT v.verdict_id, e.violation_id, e.rule_id, e.severity, e.seq, e.row_hash
                                      FROM pii_token_verdicts v JOIN evidence e ON e.verdict_id = v.verdict_id
                                      WHERE v.org = ? AND v.key_id = ? AND v.token = ? ORDER BY v.seen_at DESC""",
                                   (org, kid, token)):
                    if all(x["verdict_id"] != r["verdict_id"] for x in verdicts):
                        verdicts.append({"verdict_id": r["verdict_id"], "violation_id": r["violation_id"],
                                         "rule_id": r["rule_id"], "severity": r["severity"], "chain_seq": r["seq"],
                                         "chain_hash": r["row_hash"]})
        return {"category": category, "systems": sorted(systems.values(), key=lambda s: s["system"]),
                "verdicts": verdicts, "keys_tried": len({k for k, _ in pairs})}
