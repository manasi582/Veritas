"""
Names that agents and API callers choose (a source system, a field name, an agent label) end up on
the dashboard. The dashboard escapes everything it shows; this is the second lock: a name that
could open a tag or close a quoted value is refused where it enters, so it is never stored.
"""
from __future__ import annotations

import re

_UNSAFE = re.compile(r"[<>\"'&`\x00-\x1f\x7f]")


def check_label(value: str, what: str) -> str:
    """Return the value unchanged, or raise ValueError saying what is wrong with it."""
    if _UNSAFE.search(value):
        raise ValueError(f"{what} must not contain < > \" ' & ` or control characters.")
    return value
