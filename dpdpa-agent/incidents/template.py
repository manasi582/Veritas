"""
Turns a log line into a template that is the same for every line of the same kind, and a fingerprint from it.

    "2026-10-20 10:01:02 ERROR payment failed for order 88231 card [CARD_REDACTED] user=asha"
 -> "<TS> ERROR payment failed for order <N> card <PII:CARD> user=<*>"

What is kept is only what cannot be somebody's data: log levels, short lower-case words (the wording of the program),
punctuation, and a placeholder for every kind of value. The detected personal values are removed first (masking.py);
digits, ids, addresses, quoted text, anything capitalised or with digits in it, and whatever follows an `=` become
placeholders. A name the detector missed that is written in lower case, on its own, is the one thing this cannot
catch; the template is shown to staff, never sent anywhere, and the documentation says so.
"""
from __future__ import annotations

import hashlib
import re
from typing import Iterable, NamedTuple, Optional

from masking import mask_text

MAX_INPUT = 4000
MAX_TEMPLATE = 240

_LEVELS = {"INFO", "WARN", "WARNING", "ERROR", "DEBUG", "TRACE", "FATAL", "CRITICAL", "NOTICE", "SEVERE"}
_SUBS = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), " <TS> "),
    (re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\b"), " <TS> "),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), " <ID> "),
    (re.compile(r"https?://\S+"), " <URL> "),
    (re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), " <EMAIL> "),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), " <IP> "),
    (re.compile(r'"[^"\n]*"'), " <STR> "),
    (re.compile(r"'[^'\n]*'"), " <STR> "),
    (re.compile(r"\b(?:0x[0-9a-fA-F]{8,}|(?=[0-9]*[a-fA-F])[0-9a-fA-F]{8,})\b"), " <HEX> "),
    (re.compile(r"\b\d+(?:[.,:]\d+)*\b"), " <N> "),
]
_PLACEHOLDER = re.compile(r"\[([A-Z0-9_]+?)(?:_REDACTED|#[0-9a-f]{6}\.[0-9a-f]{16})\]")
_TOKEN = re.compile(r"<[A-Z*][A-Za-z:_*]*>|[A-Za-z][A-Za-z0-9_.\-/]*|\S")
_WORD = re.compile(r"[a-z][a-z_\-]{0,24}")

_FILE_LINE = re.compile(r"\b[\w./\\-]*?([\w-]+\.(?:py|java|go|js|ts|rb|cs|php|kt|rs|cc|cpp|scala|c|h)):(\d+)\b")
_FRAME = re.compile(r"\bat ([\w$]+(?:\.[\w$<>]+){1,8})\(([\w$.]+):(\d+)\)")
_LOGGER = re.compile(r"(?:\blogger=|\[)([a-z][\w]*(?:\.[\w]+){1,6})\]?")


class Template(NamedTuple):
    text: str
    hint: Optional[str]


def template_of(raw: str, matches: Iterable = ()) -> Template:
    """Template and root-cause hint of one log line. `matches` are the detector's findings in it."""
    text = (raw or "")[:MAX_INPUT]
    masked = mask_text(text, matches)
    hint = _hint(masked)
    s = _PLACEHOLDER.sub(lambda m: " <PII:%s> " % m.group(1), masked)
    for pattern, repl in _SUBS:
        s = pattern.sub(repl, s)
    out = []
    previous = ""
    for tok in _TOKEN.findall(s):
        if tok.startswith("<") and tok.endswith(">") and len(tok) > 2:
            keep = tok
        elif previous == "=":
            keep = "<*>"
        elif tok in _LEVELS or _WORD.fullmatch(tok):
            keep = tok
        elif len(tok) == 1 and not tok.isalnum():
            keep = tok
        else:
            keep = "<*>"
        if keep in ("<*>", "<N>", "<TS>", "<ID>") and out and out[-1] == keep:
            previous = tok
            continue
        out.append(keep)
        previous = tok
    return Template(_join(out)[:MAX_TEMPLATE], hint)


def _join(tokens) -> str:
    text = ""
    for i, tok in enumerate(tokens):
        glue = "" if (i == 0 or tok in ",.;:)]}" or tokens[i - 1] in "([{=" or tok == "=") else " "
        text += glue + tok
    return text.strip()


def _hint(masked: str) -> Optional[str]:
    parts = []
    m = _FRAME.search(masked)
    if m:
        parts.append("%s (%s:%s)" % (m.group(1), m.group(2), m.group(3)))
    else:
        m = _FILE_LINE.search(masked)
        if m:
            parts.append("%s:%s" % (m.group(1), m.group(2)))
    m = _LOGGER.search(masked)
    if m and "@" not in m.group(1):
        parts.append("logger " + m.group(1))
    return " · ".join(parts)[:160] or None


_NAME_PLACEHOLDER = "<PII:NAME>"
_REPEATED_WILDCARD = re.compile(r"<\*>(?: <\*>)+")


def _grouping_form(template: str) -> str:
    """
    The template as it is compared for grouping. A name the detector found (<PII:NAME>) and a capitalised word it did not find
    (<*>) are the same place in the same line, so they count as the same: otherwise one line shape splits into two incidents
    depending on whether the language model happened to recognise a name that day. The displayed template is unchanged.
    """
    return _REPEATED_WILDCARD.sub("<*>", template.replace(_NAME_PLACEHOLDER, "<*>"))


def fingerprint(org: str, rule_id: str, source_system: str, field: str, template: str) -> str:
    """Same finding of the same kind in the same place gives the same fingerprint. 32 hex characters."""
    material = "\n".join(("veritas-incident-v1", org, rule_id, source_system, field, _grouping_form(template)))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
