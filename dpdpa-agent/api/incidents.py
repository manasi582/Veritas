"""
Incidents (phase T2 of docs/TRUST_VISIBILITY_PLAN.md).

  GET  /v1/{org}/incidents                   list, filtered; counts, owner, sparkline          any role of the org
  GET  /v1/{org}/incidents/summary           "12,000 verdicts, 9 incidents"                    any role of the org
  GET  /v1/{org}/incidents/{id}              one incident                                      any role of the org
  GET  /v1/{org}/incidents/{id}/verdicts     the verdicts behind it                            any role of the org
  POST /v1/{org}/incidents/{id}/status       acknowledge or resolve (a chained event)          COMPLIANCE_ADMIN
  POST /v1/{org}/incidents/{id}/merge        fold another incident into this one               COMPLIANCE_ADMIN
  POST /v1/{org}/incidents/{id}/split        move named verdicts into a new incident           COMPLIANCE_ADMIN
  GET  /v1/{org}/incidents/{id}/breach-pack  draft breach report (zip), audit-logged               AUDITOR, COMPLIANCE_ADMIN
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.auth_deps import check_org_access, org_access
from config_loader import OrgConfigNotFoundError, load_org_config
from evidence_store.store import get_store
from user_store.models import User, UserRole

logger = logging.getLogger("api.incidents")
router = APIRouter(prefix="/v1", tags=["incidents"])


def _owners(org_id: str) -> Dict[str, Any]:
    try:
        return {k: v.model_dump() for k, v in (load_org_config(org_id).owners or {}).items()}
    except OrgConfigNotFoundError:
        return {}
    except Exception:
        logger.debug("owners unavailable", exc_info=True)
        return {}


def _audit(user: User, action: str, org: str, resource: str, detail: Dict[str, Any]) -> None:
    try:
        from audit_log.store import get_audit_store
        get_audit_store().log(action, actor_id=user.user_id, actor_name=user.username, org_id=org,
                              resource=resource, detail=detail)
    except Exception:
        logger.debug("audit entry failed", exc_info=True)


class StatusChange(BaseModel):
    status: str
    reason: Optional[str] = Field(default=None, max_length=500)


class MergeRequest(BaseModel):
    merge_from: str = Field(..., description="the incident to fold into this one")
    reason: Optional[str] = Field(default=None, max_length=500)


class SplitRequest(BaseModel):
    verdict_ids: List[str] = Field(..., min_length=1, max_length=5000)
    reason: Optional[str] = Field(default=None, max_length=500)


@router.get("/{org_id}/incidents/summary")
async def incident_summary(org_id: str, _user: User = Depends(check_org_access)):
    return get_store().incident_summary(org_id)


@router.get("/{org_id}/incidents")
async def list_incidents(
    org_id: str,
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source_system: Optional[str] = Query(None),
    recurred: bool = Query(False),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _user: User = Depends(check_org_access),
):
    rows, total = get_store().list_incidents(org_id, status=status, severity=severity, source_system=source_system,
                                             recurred=recurred, limit=limit, offset=offset)
    owners = _owners(org_id)
    for r in rows:
        r["owner"] = owners.get(r["source_system"])
    return {"incidents": rows, "total": total}


def _one(org_id: str, incident_id: str) -> dict:
    row = get_store().get_incident(org_id, incident_id)
    if row is None:
        raise HTTPException(404, f"Incident {incident_id!r} not found.")
    row["owner"] = _owners(org_id).get(row["source_system"])
    return row


@router.get("/{org_id}/incidents/{incident_id}")
async def get_incident(org_id: str, incident_id: str, _user: User = Depends(check_org_access)):
    return _one(org_id, incident_id)


@router.get("/{org_id}/incidents/{incident_id}/breach-pack")
async def breach_pack(org_id: str, incident_id: str,
                      user: User = Depends(org_access(UserRole.AUDITOR, UserRole.COMPLIANCE_ADMIN))):
    from fastapi.responses import Response
    from breach_pack import report
    row = _one(org_id, incident_id)
    data = report.build_zip(report.gather(get_store(), org_id, row, row.get("owner")))
    _audit(user, "BREACH_PACK_DOWNLOADED", org_id, incident_id, {"incident_number": row["number"]})
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{org_id}-incident-{row["number"]}-breach-pack.zip"'})


@router.get("/{org_id}/incidents/{incident_id}/verdicts")
async def incident_verdicts(org_id: str, incident_id: str, limit: int = Query(100, ge=1, le=500),
                            offset: int = Query(0, ge=0), _user: User = Depends(check_org_access)):
    _one(org_id, incident_id)
    return {"verdicts": get_store().incident_verdicts(org_id, incident_id, limit, offset)}


@router.post("/{org_id}/incidents/{incident_id}/status")
async def change_status(org_id: str, incident_id: str, body: StatusChange,
                        user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN))):
    _one(org_id, incident_id)
    try:
        row = get_store().set_incident_status(org_id, incident_id, body.status, actor=user.username, reason=body.reason)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(user, "INCIDENT_STATUS", org_id, f"incident:{incident_id}", {"status": body.status.upper()})
    return {"ok": True, "incident": row}


@router.post("/{org_id}/incidents/{incident_id}/merge")
async def merge_incident(org_id: str, incident_id: str, body: MergeRequest,
                         user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN))):
    try:
        row = get_store().merge_incidents(org_id, body.merge_from, incident_id, actor=user.username, reason=body.reason)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(user, "INCIDENT_MERGE", org_id, f"incident:{incident_id}", {"merged": body.merge_from})
    return {"ok": True, "incident": row}


@router.post("/{org_id}/incidents/{incident_id}/split")
async def split_incident(org_id: str, incident_id: str, body: SplitRequest,
                         user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN))):
    try:
        row = get_store().split_incident(org_id, incident_id, body.verdict_ids, actor=user.username, reason=body.reason)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(user, "INCIDENT_SPLIT", org_id, f"incident:{incident_id}", {"moved": row["count"]})
    return {"ok": True, "incident": row}
