"""
Retention review (phase D of docs/PS_ALIGNMENT_PLAN.md).

  GET  /v1/{org}/retention         each declared field against its retention period                  any role of the org
  POST /v1/{org}/retention/tasks   open a task for the owner of each named system                    COMPLIANCE_ADMIN

A task is a rights request of type `retention` (no identifiers): confirming it is a chain entry. Veritas never deletes data.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.auth_deps import check_org_access, org_access
from config_loader import OrgConfigNotFoundError, load_org_config
from evidence_store.store import get_store
from retention_review import review as retention
from subject_lookup import rights
from user_store.models import User, UserRole

logger = logging.getLogger("api.retention")
router = APIRouter(prefix="/v1", tags=["retention"])


def _cfg(org_id: str):
    try:
        return load_org_config(org_id)
    except OrgConfigNotFoundError:
        raise HTTPException(404, f"{org_id!r} has no registered policy.")


class TaskRequest(BaseModel):
    systems: List[str] = Field(..., min_length=1, max_length=50)


@router.get("/{org_id}/retention")
async def get_retention(org_id: str, _user: User = Depends(check_org_access)):
    return retention.review(get_store(), org_id, _cfg(org_id))


@router.post("/{org_id}/retention/tasks", status_code=201)
async def open_tasks(org_id: str, body: TaskRequest, user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN))):
    cfg = _cfg(org_id)
    found = retention.review(get_store(), org_id, cfg)
    known = {i["system"] for i in found["items"]}
    unknown = sorted(set(body.systems) - known)
    if unknown:
        raise HTTPException(400, "Not systems of this policy: " + ", ".join(unknown))
    detail = [{"system": i["system"], "field": i["field"], "retention_days": i["retention_days"], "due_at": i["due_at"],
               "status": i["status"]} for i in found["items"] if i["system"] in body.systems and i["status"] in ("overdue", "due soon", "past, not seen")]
    owners = {k: v.model_dump() for k, v in (cfg.owners or {}).items()}
    try:
        out = rights.create_retention_task(get_store(), org_id, body.systems, owners=owners, actor=user.username, detail=detail)
    except rights.RequestError as e:
        raise HTTPException(400, str(e))
    try:
        from audit_log.store import get_audit_store
        get_audit_store().log("RETENTION_TASK_CREATED", actor_id=user.user_id, actor_name=user.username, org_id=org_id,
                              resource=f"request:{out['request_id']}", detail={"systems": sorted(set(body.systems))})
    except Exception:
        logger.debug("audit entry failed", exc_info=True)
    return out
