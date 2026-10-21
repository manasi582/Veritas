"""
Veritas Rate Limiter
====================
In-memory sliding-window rate limiter for protecting sensitive endpoints.
No external dependencies (no Redis). Suitable for single-process deployments.

Protects:
  - POST /api/auth/login        — brute-force login prevention
  - POST /api/auth/setup        — prevent rapid admin account creation
  - POST /agent/register        — prevent registration key enumeration
  - POST /agents/issue-key      — prevent key generation flooding

Design:
  - Keyed by (endpoint, identifier) — identifier is IP address or username
  - Sliding window: counts requests within the last `window_seconds`
  - On exceed: raises HTTP 429 with Retry-After header
  - State is in-memory — resets on server restart (acceptable for rate limiting)
  - Thread-safe via threading.Lock
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

from fastapi import HTTPException, Request


class _RateLimiter:
    """
    Sliding window rate limiter.
    Stores timestamps of recent requests per (endpoint, key) pair.
    """

    def __init__(self) -> None:
        self._lock   = threading.Lock()
        # {(endpoint, key): deque of timestamps}
        self._windows: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)

    def check(
        self,
        endpoint: str,
        key: str,
        *,
        max_requests: int,
        window_seconds: int,
    ) -> None:
        """
        Record a request and raise HTTP 429 if the limit is exceeded.

        Args:
            endpoint:        Logical name for the endpoint (e.g. "login").
            key:             Per-user key (IP address or username).
            max_requests:    Maximum allowed requests in the window.
            window_seconds:  Rolling window length in seconds.
        """
        now = time.monotonic()
        cutoff = now - window_seconds
        bucket_key = (endpoint, key)

        with self._lock:
            bucket = self._windows[bucket_key]
            # Evict timestamps outside the window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            if len(bucket) >= max_requests:
                oldest = bucket[0]
                retry_after = int(oldest + window_seconds - now) + 1
                raise HTTPException(
                    status_code=429,
                    detail=(
                        f"Too many requests. "
                        f"Maximum {max_requests} attempts per {window_seconds}s. "
                        f"Try again in {retry_after}s."
                    ),
                    headers={"Retry-After": str(retry_after)},
                )

            bucket.append(now)

    def peek(
        self,
        endpoint: str,
        key: str,
        *,
        max_requests: int,
        window_seconds: int,
    ) -> None:
        """Raise HTTP 429 if the limit is already reached, WITHOUT recording a request."""
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._windows[(endpoint, key)]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= max_requests:
                retry_after = int(bucket[0] + window_seconds - now) + 1
                raise HTTPException(
                    status_code=429,
                    detail=(
                        f"Too many failed attempts. "
                        f"Maximum {max_requests} per {window_seconds}s. "
                        f"Try again in {retry_after}s."
                    ),
                    headers={"Retry-After": str(retry_after)},
                )

    def record(self, endpoint: str, key: str) -> None:
        """Record one event (for example a failed attempt) without enforcing a limit."""
        with self._lock:
            self._windows[(endpoint, key)].append(time.monotonic())

    def reset(self, endpoint: str, key: str) -> None:
        """Clear the rate limit bucket for a key (e.g. after successful login)."""
        with self._lock:
            self._windows.pop((endpoint, key), None)

    def cleanup(self) -> None:
        """Remove all empty / expired buckets. Call periodically to avoid memory growth."""
        now = time.monotonic()
        with self._lock:
            dead = [k for k, v in self._windows.items() if not v or v[-1] < now - 3600]
            for k in dead:
                del self._windows[k]


# Module-level singleton
_limiter = _RateLimiter()


def _client_ip(request: Request) -> str:
    """The client address for rate limiting. A forwarded address counts only behind a trusted proxy (request_context)."""
    from request_context import client_ip_of
    return client_ip_of(request)


# ---------------------------------------------------------------------------
# FastAPI dependency factories
# ---------------------------------------------------------------------------

def login_rate_limit(request: Request) -> None:
    """
    Dependency: rate-limit login attempts by IP.
    10 attempts per 5 minutes. Raises 429 on exceed.
    """
    _limiter.check(
        "login",
        _client_ip(request),
        max_requests=10,
        window_seconds=300,
    )


def setup_rate_limit(request: Request) -> None:
    """
    Dependency: rate-limit /setup by IP.
    10 attempts per 10 minutes: enough for typing mistakes in the code or the form, far too few
    to guess a 60-bit setup code.
    """
    _limiter.check(
        "setup",
        _client_ip(request),
        max_requests=10,
        window_seconds=600,
    )


REGISTER_FAILURE_LIMIT = 20          # failed registrations per IP per hour


def register_rate_limit(request: Request) -> None:
    """
    Dependency: block an IP that keeps presenting bad registration keys.

    Only FAILED attempts count (see record_register_failure). Successful registrations
    are bounded by the key itself (its use limit and expiry), so enrolling a whole
    cluster of agents from one egress IP is not throttled, while key guessing is.
    """
    _limiter.peek(
        "agent_register_failed",
        _client_ip(request),
        max_requests=REGISTER_FAILURE_LIMIT,
        window_seconds=3600,
    )


def record_register_failure(request: Request) -> None:
    """Count one failed registration attempt against the caller's IP."""
    _limiter.record("agent_register_failed", _client_ip(request))


def issue_key_rate_limit(request: Request) -> None:
    """
    Dependency: rate-limit registration key issuance by IP.
    30 keys per hour.
    """
    _limiter.check(
        "issue_key",
        _client_ip(request),
        max_requests=30,
        window_seconds=3600,
    )


def clear_login_limit(ip: str) -> None:
    """Call after successful login to reset the IP's failure counter."""
    _limiter.reset("login", ip)


# ---------------------------------------------------------------------------
# Per-account login lockout
# ---------------------------------------------------------------------------
# Login is also limited per IP address, which a guess spread over many addresses avoids.
# This limits failures per account name: 5 wrong attempts lock that name for 15 minutes.
# It applies to any name typed, existing or not, so it reveals nothing about which accounts exist.

ACCOUNT_MAX_FAILURES = 5
ACCOUNT_WINDOW_SECONDS = 900


def _account_key(username: str) -> str:
    return (username or "").strip().lower()[:64]


def account_lock_check(username: str) -> None:
    """Raise HTTP 429 if this account name is locked after too many failed logins."""
    _limiter.peek("acct_fail", _account_key(username),
                  max_requests=ACCOUNT_MAX_FAILURES, window_seconds=ACCOUNT_WINDOW_SECONDS)


def account_failure(username: str) -> bool:
    """Record a failed login for this name. Returns True if this failure locked it."""
    key = _account_key(username)
    _limiter.record("acct_fail", key)
    try:
        _limiter.peek("acct_fail", key, max_requests=ACCOUNT_MAX_FAILURES,
                      window_seconds=ACCOUNT_WINDOW_SECONDS)
    except HTTPException:
        return True
    return False


def account_success(username: str) -> None:
    _limiter.reset("acct_fail", _account_key(username))
