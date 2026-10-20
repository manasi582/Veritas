"""
Finds where a log line says data was sent, as a host name only (never a path, query, credentials or port).

Two places are read, and nothing is guessed beyond them:
  * structured fields with a destination-like name (destination, dest, target_url, endpoint, url, host, upstream ...);
  * a URL in the text right after a word that says "sent to" (to, ->, calling, posting to, uploaded to, POST, GET, PUT).
"""
from __future__ import annotations

import re
from typing import Dict, Optional
from urllib.parse import urlparse

_FIELD_NAMES = {"destination", "dest", "destination_host", "target", "target_url", "target_host", "endpoint", "url",
                "host", "remote_host", "upstream", "sink", "recipient_host"}
_HOST = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,98}[a-z0-9])?$")
_SNIPPET = re.compile(
    r"(?:\bto|->|=>|\bcalling|\bposting\s+to|\bsent\s+to|\buploaded?\s+to|\bforwarded?\s+to|\bPOST|\bGET|\bPUT)\s+"
    r"(https?://[^\s\"'<>]+)", re.IGNORECASE)


def _host_of(value: str) -> Optional[str]:
    value = (value or "").strip()
    if not value or len(value) > 2000:
        return None
    if "://" in value:
        try:
            host = urlparse(value).hostname
        except ValueError:
            return None
    else:
        host = value.split("/")[0].split(":")[0]
    host = (host or "").strip().lower().rstrip(".")
    return host if host and _HOST.match(host) else None


def destination_of(fields: Dict[str, str], snippet: str) -> Optional[str]:
    for key, value in (fields or {}).items():
        if key.strip().lower() in _FIELD_NAMES:
            host = _host_of(value)
            if host:
                return host
    m = _SNIPPET.search((snippet or "")[:4000])
    return _host_of(m.group(1)) if m else None
