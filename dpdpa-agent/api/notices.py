"""
Notice coverage (phase E of docs/PS_ALIGNMENT_PLAN.md).

  GET /v1/{org}/notices    the notices in the policy, and which declared fields and observed kinds of data they cover    any role of the org

Notices are part of the policy: add or change them with the policy (the Policy tab, or POST /v1/orgs/{org}/config). Coverage only:
Veritas cannot read a notice, judge whether it is adequate, or know that it was shown to anyone.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.auth_deps import check_org_access
from config_loader import OrgConfigNotFoundError, load_org_config
from evidence_store.store import get_store
from notice_registry import coverage
from user_store.models import User

router = APIRouter(prefix="/v1", tags=["notices"])


@router.get("/{org_id}/notices")
async def get_notices(org_id: str, _user: User = Depends(check_org_access)):
    try:
        cfg = load_org_config(org_id)
    except OrgConfigNotFoundError:
        raise HTTPException(404, f"{org_id!r} has no registered policy.")
    return coverage.review(get_store(), org_id, cfg)
