"""
Veritas — JWT Authentication Dependencies
==========================================
FastAPI Depends() for human user authentication.

Token lifecycle:
  - Issued at POST /api/auth/login as httpOnly cookie "veritas_session"
  - 60-minute expiry (configurable via VERITAS_JWT_EXPIRE_MINUTES)
  - HS256 signature with secret from VERITAS_JWT_SECRET env var
    (auto-generated on first start and persisted to data_root/secrets/jwt_secret.key)
  - Cookie flags: httpOnly=True, samesite="lax", secure=configurable

Separation from Agent auth:
  - Human users → JWT cookie (this module)
  - Veritas Agents → Bearer token (api/agent_auth.py, unchanged)
"""

from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Cookie, HTTPException, Request
import jwt
from jwt import PyJWTError

from user_store.models import User, UserRole
from user_store.store import get_user_store

logger = logging.getLogger("api.auth_deps")

_ALGORITHM     = "HS256"
_COOKIE_NAME   = "veritas_session"
_SECRET_FILE   = None  # set lazily

# ---------------------------------------------------------------------------
# JWT secret management
# ---------------------------------------------------------------------------

def _jwt_secret() -> str:
    """
    Return the JWT signing secret.
    Priority:
      1. VERITAS_JWT_SECRET env var
      2. Persisted secret file at data_root()/secrets/jwt_secret.key
      3. Auto-generate, persist, and return
    """
    env_secret = os.environ.get("VERITAS_JWT_SECRET", "").strip()
    if env_secret:
        return env_secret

    from runtime_paths import data_root
    secret_path = data_root() / "secrets" / "jwt_secret.key"
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    # Restrict permissions on the secrets directory
    try:
        import stat
        secret_path.parent.chmod(stat.S_IRWXU)  # 0700 — owner only
    except Exception:
        pass

    if secret_path.exists():
        return secret_path.read_text(encoding="utf-8").strip()

    new_secret = secrets.token_urlsafe(64)
    secret_path.write_text(new_secret + "\n", encoding="utf-8")
    try:
        secret_path.chmod(0o600)  # owner read/write only
    except Exception:
        pass
    logger.info("Generated new JWT signing secret at %s", secret_path)
    return new_secret


def _expire_minutes() -> int:
    try:
        return int(os.environ.get("VERITAS_JWT_EXPIRE_MINUTES", "60"))
    except ValueError:
        return 60


def _secure_cookies() -> bool:
    """
    True by default for production (HTTPS only cookies).
    Set VERITAS_SECURE_COOKIES=false for local HTTP development.
    """
    val = os.environ.get("VERITAS_SECURE_COOKIES", "true").strip().lower()
    return val not in ("false", "0", "no")


# ---------------------------------------------------------------------------
# Token operations
# ---------------------------------------------------------------------------

def create_access_token(user: User) -> str:
    """Create a signed JWT for a user. Returns the encoded token string."""
    now     = datetime.now(timezone.utc)
    expire  = now + timedelta(minutes=_expire_minutes())
    payload = {
        "sub":      user.user_id,
        "username": user.username,
        "role":     user.role.value,
        "tv":       user.token_version,
        "iat":      int(now.timestamp()),
        "exp":      int(expire.timestamp()),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=_ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT. Returns payload dict or None on any failure."""
    try:
        return jwt.decode(token, _jwt_secret(), algorithms=[_ALGORITHM])
    except PyJWTError:
        return None


def cookie_kwargs() -> dict:
    """Returns kwargs for response.set_cookie() consistent with security settings."""
    return {
        "key":      _COOKIE_NAME,
        "httponly": True,
        "samesite": "lax",
        "secure":   _secure_cookies(),
        "max_age":  _expire_minutes() * 60,
    }


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

# While an account has a temporary password, only these routes work.
PASSWORD_CHANGE_ALLOWED_PATHS = {
    "/api/auth/change-password",
    "/api/auth/logout",
    "/api/auth/me",
}


def user_from_token(token: Optional[str]) -> User:
    """
    Resolve a session token to an active user. Raises HTTPException (401 for a missing,
    invalid or unknown session; 403 for a disabled account). Shared by the HTTP dependency
    and the WebSocket handshake so both enforce exactly the same rules.
    """
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Cookie"},
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Session expired or invalid. Please log in again.",
            headers={"WWW-Authenticate": "Cookie"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Malformed session token.")

    user = get_user_store().get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User account not found.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is disabled.")
    # A password change or reset ends every session issued before it.
    if int(payload.get("tv", 0)) != user.token_version:
        raise HTTPException(
            status_code=401,
            detail="Session ended because the password was changed. Please log in again.",
            headers={"WWW-Authenticate": "Cookie"},
        )

    return user


def can_access_org(user: User, org_id: str) -> bool:
    """SUPER_ADMIN reaches every organization; everyone else only organizations they were granted."""
    if user.role == UserRole.SUPER_ADMIN:
        return True
    return get_user_store().has_org_access(user.user_id, org_id)


async def get_current_user(request: Request) -> User:
    """
    FastAPI dependency: extract and validate JWT from cookie.
    Returns the authenticated User or raises HTTP 401.

    Usage:
        @router.get("/protected")
        async def handler(user: User = Depends(get_current_user)):
            ...
    """
    user = user_from_token(request.cookies.get(_COOKIE_NAME))
    if user.must_change_password and request.url.path not in PASSWORD_CHANGE_ALLOWED_PATHS:
        raise HTTPException(
            status_code=403,
            detail="PASSWORD_CHANGE_REQUIRED: you must choose a new password before continuing.",
        )
    return user


_DENIAL_SEEN: dict = {}


def audit_denied(request: Request, user: User, reason: str, required: list, org_id: str = "") -> None:
    """
    Record a refused request: who, which route, their role and what was required. One entry per person and route every ten
    seconds, so a script hammering a closed door cannot fill the audit log. The result is DENIED, never SUCCESS.
    """
    try:
        import time
        key = (user.user_id, request.method, request.url.path)
        now = time.monotonic()
        if now - _DENIAL_SEEN.get(key, 0) < 10:
            return
        _DENIAL_SEEN[key] = now
        if len(_DENIAL_SEEN) > 5000:
            _DENIAL_SEEN.clear()
        from audit_log.store import get_audit_store
        get_audit_store().log("ACCESS_DENIED", actor_id=user.user_id, actor_name=user.username, org_id=org_id or None,
                              resource=f"{request.method} {request.url.path}", result="DENIED",
                              detail={"role": user.role.value, "reason": reason, "required": required})
    except Exception:
        pass


def org_access(*roles: UserRole):
    """
    Combined FastAPI dependency factory: checks org membership AND optional role restriction.

    - SUPER_ADMIN: always has org access (wildcard); skips role restriction too
    - Other roles: must have explicit org membership + be in allowed roles list
    - If roles=() (no roles specified): any authenticated user with org access is allowed

    Usage:
        from fastapi import Depends
        from api.auth_deps import org_access

        # Any authenticated user who has org access:
        @router.get("/{org_id}/verdicts")
        async def list_verdicts(org_id: str, _u: User = Depends(org_access())):
            ...

        # Only COMPLIANCE_ADMIN or SUPER_ADMIN with org access:
        @router.post("/{org_id}/config")
        async def upload_config(org_id: str, _u: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN))):
            ...
    """
    from fastapi import Depends

    async def _check(request: Request, org_id: str, user: User = Depends(get_current_user)) -> User:
        # SUPER_ADMIN bypasses both org-membership and role checks
        if user.role == UserRole.SUPER_ADMIN:
            return user

        # Role check (if roles were specified)
        if roles and user.role not in roles:
            audit_denied(request, user, "role", [r.value for r in roles], org_id)
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Insufficient permissions for this action "
                    f"(your role: {user.role.value}, required: {[r.value for r in roles]})"
                ),
            )

        # Org membership check
        if not get_user_store().has_org_access(user.user_id, org_id):
            audit_denied(request, user, "organization", [org_id], org_id)
            raise HTTPException(
                status_code=403,
                detail=(
                    f"You do not have access to organisation {org_id!r}. "
                    f"Ask an administrator to grant you access."
                ),
            )

        return user

    return _check


# Convenience: org access with no extra role restriction (any role that has org membership)
check_org_access = org_access()


def require_roles(*roles: UserRole):
    """
    Returns a callable for use as FastAPI Depends() that enforces role membership.

    Usage:
        from fastapi import Depends
        from api.auth_deps import require_roles
        from user_store.models import UserRole

        @router.post("/admin-only")
        async def handler(user: User = Depends(require_roles(UserRole.SUPER_ADMIN))):
            ...

        # Multiple allowed roles:
        @router.post("/admin-or-compliance")
        async def handler(
            user: User = Depends(require_roles(UserRole.SUPER_ADMIN, UserRole.COMPLIANCE_ADMIN))
        ):
            ...
    """
    from fastapi import Depends

    async def _check(request: Request, user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            audit_denied(request, user, "role", [r.value for r in roles])
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Insufficient permissions. "
                    f"Your role ({user.role.value}) does not permit this action. "
                    f"Required: {[r.value for r in roles]}"
                ),
            )
        return user

    return _check
