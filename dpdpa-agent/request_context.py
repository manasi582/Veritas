"""
Who is calling: the client address of the request being served, kept for the audit log.

The address is the connection's peer. A forwarded address (X-Forwarded-For) is believed only when the administrator has said a
reverse proxy is in front of Veritas (VERITAS_TRUSTED_PROXY=true); otherwise any client could write any address into the audit log or
slip under a per-address rate limit by sending a header.
"""
from __future__ import annotations

import contextvars
import os
from typing import Optional

_client_ip: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("veritas_client_ip", default=None)


def trusted_proxy() -> bool:
    return os.environ.get("VERITAS_TRUSTED_PROXY", "").strip().lower() in ("1", "true", "yes")


def client_ip_of(request) -> str:
    if trusted_proxy():
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if getattr(request, "client", None) else "unknown")[:64]


def set_client_ip(ip: Optional[str]):
    return _client_ip.set(ip)


def current_client_ip() -> Optional[str]:
    return _client_ip.get()
