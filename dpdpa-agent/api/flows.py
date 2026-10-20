"""
Observed processing map and record (phase T3 of docs/TRUST_VISIBILITY_PLAN.md). Counts only, never values.

  GET /v1/{org}/flows                  nodes (systems), edges (destinations), status colours     any role of the org
  GET /v1/{org}/flows/export?format=   the "record of observed processing" as csv or json        any role of the org
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, Response

from api.auth_deps import check_org_access
from config_loader import OrgConfigNotFoundError, load_org_config
from evidence_store.store import get_store
from flows import build
from user_store.models import User

logger = logging.getLogger("api.flows")
router = APIRouter(prefix="/v1", tags=["flows"])


def _map(org_id: str) -> dict:
    try:
        cfg = load_org_config(org_id)
    except OrgConfigNotFoundError:
        cfg = None
    return build.build(get_store(), org_id, cfg)


@router.get("/{org_id}/flows")
async def get_flows(org_id: str, _user: User = Depends(check_org_access)):
    return _map(org_id)


@router.get("/{org_id}/flows/export")
async def export_flows(org_id: str, format: str = Query("csv", pattern="^(csv|json)$"),
                       _user: User = Depends(check_org_access)):
    m = _map(org_id)
    if format == "json":
        return JSONResponse({**m, "title": "Record of observed processing", "rows": build.record_rows(m)})
    return Response(build.record_csv(m), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="observed-processing-{org_id}.csv"'})
