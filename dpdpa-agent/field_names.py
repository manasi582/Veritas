"""Names of structured fields, shared by the registry (server) and the detection workers (which read no settings)."""
from __future__ import annotations

import re


def field_leaf(field_name: str) -> str:
    """
    The last segment of a structured field path: `user.phone` -> `phone`, `items[0].mobile` -> `mobile`,
    `/customer/email` -> `email`. A field with no path is returned unchanged. Payloads from APIs name their
    fields by path, while the policy declares the field by its own name.
    """
    leaf = re.split(r"[./]", re.sub(r"\[[^\]]*\]", "", field_name or ""))[-1]
    return leaf or field_name
