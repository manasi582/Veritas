"""
Reads the DDL statements found in database logs and migration files, for PostgreSQL and MySQL, and returns the column
changes in them. It reads structure only: a statement that carries values (INSERT, UPDATE, COPY) is ignored, never echoed.

Understood: CREATE TABLE (each column), ALTER TABLE with ADD [COLUMN], DROP [COLUMN], RENAME [COLUMN] a TO b,
ALTER [COLUMN] c [SET DATA] TYPE t (PostgreSQL), MODIFY [COLUMN] c t and CHANGE [COLUMN] a b t (MySQL), and DROP TABLE.
Quoting with "x", `x` and [x], schema prefixes (public.customers), IF [NOT] EXISTS, ONLY, comments and statements
spread over several lines are handled. Anything else is counted as unrecognised by the caller, not guessed at.
"""
from __future__ import annotations

import re
from typing import List, NamedTuple, Optional

MAX_TEXT = 20_000
ADD, DROP, RENAME, ALTER_TYPE, DROP_TABLE = "ADD_COLUMN", "DROP_COLUMN", "RENAME_COLUMN", "ALTER_TYPE", "DROP_TABLE"


class Change(NamedTuple):
    action: str
    table: str
    column: Optional[str]
    type: Optional[str] = None
    new_name: Optional[str] = None


_IDENT = r'(?:"[^"]+"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][\w$]*)'
_QUALIFIED = rf"{_IDENT}(?:\s*\.\s*{_IDENT})*"
_COMMENTS = re.compile(r"--[^\n]*|/\*.*?\*/|#[^\n]*", re.S)
_CREATE = re.compile(rf"\bCREATE\s+(?:(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP|TEMPORARY)\s+|UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({_QUALIFIED})\s*\(", re.I)
_ALTER = re.compile(rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?({_QUALIFIED})\s+", re.I)
_DROP_TABLE = re.compile(rf"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?({_QUALIFIED}(?:\s*,\s*{_QUALIFIED})*)", re.I)
_CONSTRAINT_START = re.compile(r"^(?:CONSTRAINT|PRIMARY|FOREIGN|UNIQUE|CHECK|INDEX|KEY|FULLTEXT|SPATIAL|LIKE|EXCLUDE|PERIOD)\b", re.I)
_COL_DEF = re.compile(rf"^({_IDENT})\s+(.+)$", re.S)
_TYPE_END = re.compile(r"\s+(?:NOT\s+NULL|NULL|DEFAULT|PRIMARY|UNIQUE|REFERENCES|CHECK|COLLATE|GENERATED|CONSTRAINT|COMMENT|AUTO_INCREMENT|ON\s+UPDATE|FIRST|AFTER|USING)\b.*$", re.I | re.S)


def _unquote(name: str) -> str:
    name = name.strip()
    if len(name) >= 2 and name[0] in '"`[' and name[-1] in '"`]':
        return name[1:-1]
    return name


def _last_part(qualified: str) -> str:
    parts = re.findall(_IDENT, qualified)
    return _unquote(parts[-1]) if parts else _unquote(qualified)


def _split_top_level(text: str) -> List[str]:
    """Split on commas that are not inside parentheses or quotes."""
    out, depth, quote, cur = [], 0, "", []
    for ch in text:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def _body_of_create(text: str, start: int) -> str:
    """The text between the parenthesis opened at `start - 1` and its match."""
    depth, quote = 1, ""
    for i in range(start, len(text)):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start:i]
    return text[start:]


def _type_of(rest: str) -> str:
    return _TYPE_END.sub("", rest.strip()).strip().rstrip(";")[:60]


def _column(defn: str):
    m = _COL_DEF.match(defn.strip())
    return (_unquote(m.group(1)), _type_of(m.group(2))) if m else (None, None)


def parse(text: str) -> List[Change]:
    """The column changes in `text` (empty if none, or if it is not DDL this module reads)."""
    text = _COMMENTS.sub(" ", (text or "")[:MAX_TEXT])
    text = re.sub(r"\s+", " ", text)
    changes: List[Change] = []

    for m in _CREATE.finditer(text):
        table = _last_part(m.group(1))
        for part in _split_top_level(_body_of_create(text, m.end())):
            if not part or _CONSTRAINT_START.match(part):
                continue
            col, typ = _column(part)
            if col:
                changes.append(Change(ADD, table, col, typ))

    for m in _ALTER.finditer(text):
        table = _last_part(m.group(1))
        tail = text[m.end():]
        end = tail.find(";")
        for part in _split_top_level(tail if end < 0 else tail[:end]):
            p = part.strip()
            if (a := re.match(rf"ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?({_IDENT})\s+(.+)$", p, re.I)) \
                    and not _CONSTRAINT_START.match(p[3:].strip()):
                changes.append(Change(ADD, table, _unquote(a.group(1)), _type_of(a.group(2))))
            elif (a := re.match(rf"DROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?({_IDENT})(?=\s|,|;|$)", p, re.I)) \
                    and not re.match(r"DROP\s+(?:CONSTRAINT|INDEX|KEY|PRIMARY|FOREIGN|CHECK|DEFAULT)\b", p, re.I):
                changes.append(Change(DROP, table, _unquote(a.group(1))))
            elif a := re.match(rf"RENAME\s+(?:COLUMN\s+)?({_IDENT})\s+TO\s+({_IDENT})", p, re.I):
                changes.append(Change(RENAME, table, _unquote(a.group(1)), None, _unquote(a.group(2))))
            elif a := re.match(rf"ALTER\s+(?:COLUMN\s+)?({_IDENT})\s+(?:SET\s+DATA\s+)?TYPE\s+(.+)$", p, re.I):
                changes.append(Change(ALTER_TYPE, table, _unquote(a.group(1)), _type_of(a.group(2))))
            elif a := re.match(rf"MODIFY\s+(?:COLUMN\s+)?({_IDENT})\s+(.+)$", p, re.I):
                changes.append(Change(ALTER_TYPE, table, _unquote(a.group(1)), _type_of(a.group(2))))
            elif a := re.match(rf"CHANGE\s+(?:COLUMN\s+)?({_IDENT})\s+({_IDENT})\s+(.+)$", p, re.I):
                changes.append(Change(RENAME, table, _unquote(a.group(1)), _type_of(a.group(3)), _unquote(a.group(2))))

    for m in _DROP_TABLE.finditer(text):
        for name in re.split(r"\s*,\s*", m.group(1)):
            changes.append(Change(DROP_TABLE, _last_part(name), None))
    return changes
