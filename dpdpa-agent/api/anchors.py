"""
Anchoring and evidence export (phase T1 of docs/TRUST_VISIBILITY_PLAN.md).

  GET  /v1/{org}/anchors           checkpoints with their status and receipts      AUDITOR and above
  POST /v1/{org}/anchors/run       take a checkpoint now                           COMPLIANCE_ADMIN
  GET  /v1/{org}/anchors/export    the signed checkpoints (JSON lines)             AUDITOR and above, audit-logged
  GET  /v1/{org}/anchors/pubkey    the public key that verifies them               AUDITOR and above
  GET  /v1/{org}/evidence/export   the whole chain (JSON lines)                    AUDITOR and above, audit-logged

Anchoring is off until configured (docs/ANCHORING.md); the export works either way.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse

from anchoring import checkpoints as anchor_cps
from anchoring import export as anchor_export
from api.auth_deps import org_access
from evidence_store.store import get_store
from user_store.models import User, UserRole

logger = logging.getLogger("api.anchors")
router = APIRouter(prefix="/v1", tags=["anchoring"])


def _audit(user: User, action: str, org: str, detail: Dict[str, Any]) -> None:
    try:
        from audit_log.store import get_audit_store
        get_audit_store().log(action, actor_id=user.user_id, actor_name=user.username, org_id=org, detail=detail)
    except Exception:
        logger.debug("audit entry failed", exc_info=True)


@router.get("/{org_id}/anchors")
async def list_anchors(org_id: str, _user: User = Depends(org_access(UserRole.AUDITOR, UserRole.COMPLIANCE_ADMIN))):
    manager = anchor_cps.get_manager()
    if manager is None:
        return {"enabled": False, "checkpoints": [], "status": {"enabled": False}}
    return {"enabled": True, "checkpoints": manager.list_checkpoints(org_id), "status": manager.status(org_id)}


@router.post("/{org_id}/anchors/run")
async def run_anchor(org_id: str, user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN))):
    manager = anchor_cps.get_manager()
    if manager is None:
        raise HTTPException(status_code=409, detail="Anchoring is not turned on. See docs/ANCHORING.md.")
    created = manager.checkpoint_now(org_id)
    manager.publish_pending(org_id)
    _audit(user, "ANCHOR_RUN", org_id, {"created": bool(created)})
    return {"created": bool(created), "checkpoint": created,
            "message": None if created else "Nothing new to anchor: the chain has not changed since the last checkpoint."}


@router.get("/{org_id}/anchors/export")
async def export_anchors(org_id: str, user: User = Depends(org_access(UserRole.AUDITOR, UserRole.COMPLIANCE_ADMIN))):
    manager = anchor_cps.get_manager()
    lines = anchor_export.checkpoint_lines(manager, org_id) if manager else iter(())
    _audit(user, "ANCHORS_EXPORTED", org_id, {})
    return StreamingResponse(lines, media_type="application/x-ndjson",
                             headers={"Content-Disposition": f'attachment; filename="{org_id}-checkpoints.jsonl"'})


@router.get("/{org_id}/anchors/pubkey", response_class=PlainTextResponse)
async def anchors_pubkey(org_id: str, _user: User = Depends(org_access(UserRole.AUDITOR, UserRole.COMPLIANCE_ADMIN))):
    return anchor_export.public_key_text()


@router.get("/{org_id}/evidence/export")
async def export_evidence(org_id: str, user: User = Depends(org_access(UserRole.AUDITOR, UserRole.COMPLIANCE_ADMIN))):
    store = get_store()
    _audit(user, "EVIDENCE_EXPORTED", org_id, {"records": store.chain_head(org_id)["record_count"]})
    return StreamingResponse(anchor_export.evidence_lines(store, org_id), media_type="application/x-ndjson",
                             headers={"Content-Disposition": f'attachment; filename="{org_id}-evidence.jsonl"'})
