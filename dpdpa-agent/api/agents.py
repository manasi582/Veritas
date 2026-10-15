"""
Veritas Agent Management API
================================
Admin-facing routes (require human JWT auth):
    POST /agents/issue-key          Issue one-time registration key
    GET  /agents                    List agents
    GET  /agents/{agent_id}         Agent detail
    POST /agents/{agent_id}/revoke  Revoke agent

Agent-facing routes (require Agent Bearer token, NOT human auth):
    POST /agent/register            Bootstrap registration (key-based)
    POST /agent/heartbeat           Heartbeat update (agent token)
"""

from __future__ import annotations

import logging
from typing import Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from agent_store.models import Agent, AgentStatus
from agent_store.store import get_agent_store
from api.agent_auth import verify_agent_token
from api.auth_deps import can_access_org as _can_access_org, get_current_user, require_roles
from config_loader import OrgConfigNotFoundError, load_org_config
from rate_limit import issue_key_rate_limit, record_register_failure, register_rate_limit
from user_store.models import User, UserRole
from user_store.store import get_user_store
from labels import check_label
from veritas_version import MIN_AGENT_VERSION, get_version, is_agent_outdated

logger = logging.getLogger("api.agents")

router = APIRouter(tags=["agent_management"])


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _require_org(org_id: str) -> None:
    """Raise 404 if org_id has no registered config."""
    try:
        load_org_config(org_id)
    except OrgConfigNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=(
                f"org_id {org_id!r} has no registered config. "
                f"Register one first via POST /v1/orgs/{org_id}/config."
            ),
        )


def _require_org_access(user: User, org_id: str) -> None:
    if not _can_access_org(user, org_id):
        raise HTTPException(
            status_code=403,
            detail=(
                f"You do not have access to organisation {org_id!r}. "
                f"Ask an administrator to grant you access."
            ),
        )


def _agent_visible_to(user: User, agent: Agent) -> bool:
    return _can_access_org(user, agent.org_id)


def _agent_to_dict(agent: Agent) -> dict:
    return {
        "agent_id": agent.agent_id,
        "org_id": agent.org_id,
        "status": agent.status.value,
        "source_label": agent.source_label,
        "created_at": agent.created_at.isoformat(),
        "last_heartbeat_at": agent.last_heartbeat_at.isoformat() if agent.last_heartbeat_at else None,
        "events_received": agent.events_received,
        "agent_version": agent.agent_version,
        "outdated": is_agent_outdated(agent.agent_version),
        "health": agent.health,
        "health_updated_at": agent.health_updated_at.isoformat() if agent.health_updated_at else None,
    }


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

SINGLE_USE_TTL_SECONDS = 1800          # 30 minutes
REUSABLE_DEFAULT_TTL_SECONDS = 86400   # 24 hours
MAX_KEY_TTL_SECONDS = 30 * 86400       # 30 days
MAX_KEY_USES = 10000


class IssueKeyRequest(BaseModel):
    org_id: str = Field(..., min_length=1)
    # 1 = a normal one-time key. More than 1 = a reusable enrollment key, for example
    # for a Kubernetes DaemonSet where every node's agent registers itself.
    max_uses: int = Field(1, ge=1, le=MAX_KEY_USES)
    expires_in_seconds: Optional[int] = Field(None, ge=60, le=MAX_KEY_TTL_SECONDS)
    label: str = Field("", max_length=100)


class IssueKeyResponse(BaseModel):
    key: str
    org_id: str
    expires_in_seconds: int
    key_id: str = ""
    max_uses: int = 1
    expires_at: str = ""
    label: str = ""


class RegisterAgentRequest(BaseModel):
    registration_key: str = Field(..., min_length=1, max_length=500)
    source_label: str = Field(default="", max_length=200, description="Human label for this agent, e.g. 'order-service'")

    @field_validator("source_label")
    @classmethod
    def _label_is_plain(cls, v):
        return check_label(v, "source_label")


class RegisterAgentResponse(BaseModel):
    agent_id:       str
    auth_token:     str
    org_id:         str
    event_endpoint: str
    server_version: str = ""          # lets the agent notice a version mismatch
    min_agent_version: str = ""


class SourceHealth(BaseModel):
    """State of one log source the agent is reading."""
    type: str = Field(..., max_length=16)
    target: str = Field("", max_length=300)          # file path or container name
    source_system: str = Field("", max_length=200)
    state: Literal["reading", "waiting", "error"] = "waiting"
    detail: str = Field("", max_length=200)           # short reason when state is "error"
    last_line_at: Optional[str] = Field(None, max_length=40)


class AgentHealth(BaseModel):
    """
    Health report an agent attaches to its heartbeat. Everything is bounded: the
    agent is untrusted input, and this is stored and shown to administrators.
    Never contains event text.
    """
    agent_version: str = Field("", max_length=64)
    uptime_seconds: int = Field(0, ge=0)
    queue_depth: int = Field(0, ge=0)
    queue_capacity: int = Field(0, ge=0)
    counters: Dict[str, int] = Field(default_factory=dict)
    sources: List[SourceHealth] = Field(default_factory=list)

    @field_validator("counters")
    @classmethod
    def _bound_counters(cls, v: Dict[str, int]) -> Dict[str, int]:
        if len(v) > 20 or any(len(k) > 40 for k in v):
            raise ValueError("too many counters or counter name too long")
        return v

    @field_validator("sources")
    @classmethod
    def _bound_sources(cls, v: List[SourceHealth]) -> List[SourceHealth]:
        if len(v) > 50:
            raise ValueError("too many sources (max 50)")
        return v


class HeartbeatRequest(BaseModel):
    agent_id: str = Field(..., min_length=1)
    health: Optional[AgentHealth] = None   # absent for agents older than v1.0.18


# ---------------------------------------------------------------------------
# Admin-facing endpoints
# ---------------------------------------------------------------------------

@router.post("/agents/issue-key", response_model=IssueKeyResponse)
async def issue_registration_key(
    req: IssueKeyRequest,
    _user: User = Depends(require_roles(UserRole.SUPER_ADMIN, UserRole.COMPLIANCE_ADMIN)),
    _rl: None = Depends(issue_key_rate_limit),
) -> IssueKeyResponse:
    """
    Issue a registration key for an org.

    By default a one-time key that expires in 30 minutes. With max_uses > 1 it is a
    reusable enrollment key (default 24 hours, at most 30 days) that lets that many
    agents register, for example one per Kubernetes node. The plaintext key is returned
    once and never stored; revoke a key with POST /agents/keys/{key_id}/revoke.
    """
    _require_org(req.org_id)
    _require_org_access(_user, req.org_id)

    ttl_seconds = req.expires_in_seconds
    if ttl_seconds is None:
        ttl_seconds = SINGLE_USE_TTL_SECONDS if req.max_uses == 1 else REUSABLE_DEFAULT_TTL_SECONDS

    plaintext, key = get_agent_store().issue_key_detailed(
        req.org_id,
        max_uses=req.max_uses,
        ttl_minutes=max(1, round(ttl_seconds / 60)),
        label=req.label.strip(),
        created_by=_user.username,
    )

    logger.info("Admin issued registration key %s for org %r (max_uses=%d)",
                key.key_id, req.org_id, req.max_uses)
    try:
        from audit_log.store import AuditAction, get_audit_store
        get_audit_store().log(AuditAction.AGENT_KEY_ISSUED, actor_id=_user.user_id,
                              actor_name=_user.username, org_id=req.org_id,
                              resource=f"key:{key.key_id}",
                              detail={"max_uses": req.max_uses, "label": key.label,
                                      "expires_at": key.expires_at.isoformat()})
    except Exception:
        pass
    return IssueKeyResponse(
        key=plaintext,
        org_id=req.org_id,
        expires_in_seconds=ttl_seconds,
        key_id=key.key_id,
        max_uses=key.max_uses,
        expires_at=key.expires_at.isoformat(),
        label=key.label,
    )


def _key_to_dict(key) -> dict:
    return {
        "key_id": key.key_id,
        "org_id": key.org_id,
        "label": key.label,
        "created_at": key.created_at.isoformat(),
        "created_by": key.created_by,
        "expires_at": key.expires_at.isoformat(),
        "max_uses": key.max_uses,
        "uses": key.uses,
        "revoked": key.revoked,
        "status": key.status(),
    }


# NOTE: the /agents/keys routes are declared before /agents/{agent_id} on purpose,
# otherwise "keys" would be captured as an agent id.

@router.get("/agents/keys")
async def list_registration_keys(
    org_id: str,
    _user: User = Depends(require_roles(UserRole.SUPER_ADMIN, UserRole.COMPLIANCE_ADMIN)),
) -> dict:
    """Keys issued for an organization (metadata only; the key value is never stored)."""
    _require_org_access(_user, org_id)
    return {"keys": [_key_to_dict(k) for k in get_agent_store().list_keys(org_id)]}


@router.post("/agents/keys/{key_id}/revoke")
async def revoke_registration_key(
    key_id: str,
    _user: User = Depends(require_roles(UserRole.SUPER_ADMIN, UserRole.COMPLIANCE_ADMIN)),
) -> dict:
    """
    Stop a key from enrolling any more agents. Agents that already registered with it
    are not affected (revoke those individually).
    """
    key = get_agent_store().get_key(key_id)
    if key is None or not _can_access_org(_user, key.org_id):
        raise HTTPException(status_code=404, detail=f"Key {key_id!r} not found.")
    get_agent_store().revoke_key(key_id)
    try:
        from audit_log.store import AuditAction, get_audit_store
        get_audit_store().log(AuditAction.AGENT_KEY_REVOKED, actor_id=_user.user_id,
                              actor_name=_user.username, org_id=key.org_id,
                              resource=f"key:{key_id}")
    except Exception:
        pass
    return {"ok": True, "key_id": key_id, "status": "REVOKED"}


@router.get("/agents")
async def list_agents(org_id: Optional[str] = None, _user: User = Depends(get_current_user)) -> dict:
    """
    List all registered agents, optionally filtered by org_id.
    Called by the admin UI's Agents section.
    """
    if org_id is not None:
        _require_org_access(_user, org_id)
        agents = get_agent_store().list_agents(org_id=org_id)
    else:
        # No filter: everything for SUPER_ADMIN, otherwise only the user's own orgs.
        agents = [a for a in get_agent_store().list_agents() if _agent_visible_to(_user, a)]
    return {"agents": [_agent_to_dict(a) for a in agents]}


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str, _user: User = Depends(get_current_user)) -> dict:
    """Single agent detail by agent_id."""
    agent = get_agent_store().get_agent(agent_id)
    if agent is None or not _agent_visible_to(_user, agent):
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} not found.")
    return _agent_to_dict(agent)


@router.post("/agents/{agent_id}/revoke")
async def revoke_agent(
    agent_id: str,
    _user: User = Depends(require_roles(UserRole.SUPER_ADMIN, UserRole.COMPLIANCE_ADMIN)),
) -> dict:
    """
    Revoke an agent. Subsequent telemetry from this agent will be rejected
    with 403. The agent record is kept for audit purposes.
    """
    target = get_agent_store().get_agent(agent_id)
    if target is None or not _agent_visible_to(_user, target):
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} not found.")
    found = get_agent_store().revoke_agent(agent_id)
    if not found:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} not found.")
    logger.info("Admin revoked agent %s", agent_id)
    try:
        from audit_log.store import AuditAction, get_audit_store
        get_audit_store().log(AuditAction.AGENT_REVOKED, actor_id=_user.user_id, actor_name=_user.username,
                              resource=f"agent:{agent_id}")
    except Exception:
        pass
    return {"ok": True, "agent_id": agent_id, "status": "REVOKED"}


# ---------------------------------------------------------------------------
# Agent-facing endpoints
# ---------------------------------------------------------------------------

@router.post("/agent/register", response_model=RegisterAgentResponse)
async def register_agent(
    req: RegisterAgentRequest,
    request: Request,
    _rl: None = Depends(register_rate_limit),
) -> RegisterAgentResponse:
    """
    Agent bootstrap registration.
    The Agent presents the one-time registration key it was configured with.
    On success, returns: agent_id, auth_token (show once), org_id, event_endpoint.
    The Agent stores these and uses auth_token for all subsequent /events calls.
    """
    store = get_agent_store()

    try:
        reg_key = store.consume_key(req.registration_key)
    except ValueError as exc:
        record_register_failure(request)   # only failed attempts count toward the rate limit
        raise HTTPException(status_code=400, detail=str(exc))

    agent, plaintext_token = store.create_agent(reg_key.org_id, req.source_label, key_id=reg_key.key_id)
    try:
        from audit_log.store import AuditAction, get_audit_store
        get_audit_store().log(AuditAction.AGENT_REGISTERED, actor_name=f"agent:{agent.agent_id}",
                              org_id=reg_key.org_id, resource=f"agent:{agent.agent_id}",
                              detail={"key_id": reg_key.key_id, "label": req.source_label,
                                      "uses": reg_key.uses, "max_uses": reg_key.max_uses})
    except Exception:
        pass

    logger.info(
        "Agent %s registered for org %r (source: %r)",
        agent.agent_id, agent.org_id, req.source_label,
    )

    return RegisterAgentResponse(
        agent_id=agent.agent_id,
        auth_token=plaintext_token,
        org_id=agent.org_id,
        event_endpoint=f"/v1/{agent.org_id}/events",
        server_version=get_version(),
        min_agent_version=MIN_AGENT_VERSION,
    )


@router.post("/agent/heartbeat")
async def agent_heartbeat(
    req: HeartbeatRequest,
    authorization: Optional[str] = Header(default=None),
) -> dict:
    """
    Agent heartbeat — updates last_heartbeat_at.
    Requires a valid Bearer token (same token issued at registration).
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header.",
        )

    token = authorization.removeprefix("Bearer ").strip()
    agent = get_agent_store().validate_token(token)

    if agent is None:
        raise HTTPException(status_code=401, detail="Unknown or invalid agent token.")

    if agent.status == AgentStatus.REVOKED:
        raise HTTPException(status_code=403, detail="Agent has been revoked.")

    # Verify the agent_id in the request matches the token owner
    if agent.agent_id != req.agent_id:
        raise HTTPException(
            status_code=403,
            detail="Token does not match the agent_id in the request.",
        )

    get_agent_store().record_heartbeat(
        agent.agent_id,
        health=req.health.model_dump() if req.health is not None else None,
    )
    reported = req.health.agent_version if req.health is not None else ""
    return {
        "ok": True,
        "agent_id": agent.agent_id,
        "server_version": get_version(),
        "min_agent_version": MIN_AGENT_VERSION,
        "agent_outdated": is_agent_outdated(reported),
    }
