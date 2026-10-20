"""
Industry policy packs (docs/POLICY_PACKS.md).

  GET  /v1/policy-packs                         the packs                                           any signed-in user
  GET  /v1/policy-packs/{id}                    one pack with the reason for every value           any signed-in user
  POST /v1/{org}/policy-packs/{id}/preview      what applying it would add (saves nothing)        AUDITOR, COMPLIANCE_ADMIN
  POST /v1/{org}/policy-packs/{id}/apply        add it to the organization's policy               COMPLIANCE_ADMIN, audit-logged

A pack that no lawyer has reviewed (status DRAFT) is applied only when the request says it was told so.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.auth_deps import get_current_user, org_access
from org_config.store import get_config_raw, upload_org_config
from policy_packs import loader
from registry.loader import reload_org_config
from user_store.models import User, UserRole

logger = logging.getLogger("api.policy_packs")
router = APIRouter(prefix="/v1", tags=["policy-packs"])


class PackRequest(BaseModel):
    system_map: Dict[str, str] = Field(default_factory=dict, description="pack system -> your system; with a map, only mapped systems are used")
    owners: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="your system -> {team, email, slack_channel}, for systems that have no owner yet")
    acknowledge_unreviewed: bool = Field(default=False, description="required to apply a pack no lawyer has reviewed")


def _plan(org_id: str, pack_id: str, body: PackRequest) -> dict:
    try:
        pack = loader.get_pack(pack_id)
        return loader.merge(pack, get_config_raw(org_id), org_id, body.system_map, body.owners)
    except loader.PackError as e:
        raise HTTPException(404 if "No policy pack" in str(e) else 400, str(e))


@router.get("/policy-packs")
async def packs(_user: User = Depends(get_current_user)):
    return {"packs": loader.list_packs()}


@router.get("/policy-packs/{pack_id}")
async def one_pack(pack_id: str, _user: User = Depends(get_current_user)):
    try:
        return loader.get_pack(pack_id)
    except loader.PackError as e:
        raise HTTPException(404, str(e))


@router.post("/{org_id}/policy-packs/{pack_id}/preview")
async def preview(org_id: str, pack_id: str, body: PackRequest = PackRequest(),
                  _user: User = Depends(org_access(UserRole.AUDITOR, UserRole.COMPLIANCE_ADMIN))):
    return _plan(org_id, pack_id, body)


@router.post("/{org_id}/policy-packs/{pack_id}/apply", status_code=201)
async def apply(org_id: str, pack_id: str, body: PackRequest = PackRequest(),
                user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN))):
    plan = _plan(org_id, pack_id, body)
    if plan["unreviewed"] and not body.acknowledge_unreviewed:
        raise HTTPException(409, "This pack has not been reviewed by a lawyer. Set acknowledge_unreviewed to apply it anyway.")
    if plan["errors"]:
        raise HTTPException(400, {"message": "The result is not a valid policy.", "errors": plan["errors"]})
    if not plan["added"]:
        return {**{k: v for k, v in plan.items() if k != "policy"}, "saved": False, "message": "Nothing to add: the policy already holds these fields."}
    result = upload_org_config(org_id, plan["policy"])
    if result["status"] != "ok":
        raise HTTPException(400, {"message": "The policy was not saved.", "errors": result["errors"]})
    reload_org_config(org_id)
    try:
        from audit_log.store import get_audit_store
        get_audit_store().log("POLICY_PACK_APPLIED", actor_id=user.user_id, actor_name=user.username, org_id=org_id,
                              resource=f"policy_pack:{pack_id}@{plan['pack']['version']}",
                              detail={"added": len(plan["added"]), "skipped": len(plan["skipped"]), "version": result["version"],
                                      "unreviewed_pack": plan["unreviewed"]})
    except Exception:
        logger.debug("audit entry failed", exc_info=True)
    return {**{k: v for k, v in plan.items() if k != "policy"}, "saved": True, "version": result["version"]}
