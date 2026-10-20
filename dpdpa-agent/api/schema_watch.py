"""
Database schema changes seen in the organization's database logs (phase B of docs/PS_ALIGNMENT_PLAN.md).

  GET /v1/{org}/schema     recent column changes that look like personal data, declared or not    any role of the org

Counts and names only: the statement text is not stored.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.auth_deps import check_org_access
from evidence_store.store import get_store
from schema_watch import evaluate
from user_store.models import User

router = APIRouter(prefix="/v1", tags=["schema"])


@router.get("/{org_id}/schema")
async def schema_changes(org_id: str, limit: int = Query(200, ge=1, le=1000), _user: User = Depends(check_org_access)):
    return evaluate.listing(get_store(), org_id, limit)
