"""
The rules in force, changes to them, and why a finding fired (docs/RULES.md).

  GET  /v1/{org}/rules                          the six rules, what each looks at, the approved setting in force      any role of the org
  GET  /v1/{org}/rules/changes                  proposals and decisions (filter: status, kind)                         any role of the org
  POST /v1/{org}/rules/changes                  propose an overlay or an exception                                     COMPLIANCE_ADMIN
  POST /v1/{org}/rules/changes/{id}/approve     approve (a different person; the same one only in a single-admin org)  COMPLIANCE_ADMIN
  POST /v1/{org}/rules/changes/{id}/reject      reject                                                                 COMPLIANCE_ADMIN
  POST /v1/{org}/rules/changes/{id}/withdraw    withdraw your own proposal                                             COMPLIANCE_ADMIN
  POST /v1/{org}/rules/changes/{id}/revoke      end an approved exception early                                        COMPLIANCE_ADMIN
  GET  /v1/{org}/rules/exceptions               approved exceptions, with how many findings each covered               any role of the org
  GET  /v1/{org}/findings/{n}/why               why finding n fired: the rule's clauses, answered                      any role of the org

Every change is audit-logged and is a RULE_EVENT in the evidence chain.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.auth_deps import check_org_access, org_access
from evidence_store.store import get_store
from rulebook import changes, specs, trace
from user_store.models import User, UserRole
from user_store.store import get_user_store

logger = logging.getLogger("api.rulebook")
router = APIRouter(prefix="/v1", tags=["rules"])


class ProposeBody(BaseModel):
    kind: str = Field(..., description="OVERLAY or EXCEPTION")
    target: Optional[str] = Field(default=None, description="the rule id, for an overlay")
    setting: Dict[str, Any]
    reason: Optional[str] = Field(default=None, max_length=500)


class DecisionBody(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500)


def _audit(user: User, action: str, org: str, resource: str, detail: Dict[str, Any]) -> None:
    try:
        from audit_log.store import get_audit_store
        get_audit_store().log(action, actor_id=user.user_id, actor_name=user.username, org_id=org, resource=resource, detail=detail)
    except Exception:
        logger.debug("audit entry failed", exc_info=True)


def single_admin(org: str) -> bool:
    """True when at most one active person can approve for this organization (then self-approval is allowed, and recorded)."""
    users = get_user_store()
    ids = set(users.get_org_users(org))
    approvers = set()
    for u in users.list_users():
        if not getattr(u, "is_active", True):
            continue
        if u.role == UserRole.SUPER_ADMIN or (u.role == UserRole.COMPLIANCE_ADMIN and u.user_id in ids):
            approvers.add(u.user_id)
    return len(approvers) <= 1


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except changes.ChangeError as e:
        raise HTTPException(404 if str(e) == "Change not found." else 400, str(e))


@router.get("/{org_id}/rules")
async def rules(org_id: str, _user: User = Depends(check_org_access)):
    store = get_store()
    in_force = changes.active(store, org_id)
    pending = changes.list_changes(store, org_id, status=changes.PROPOSED)
    return {"rules": [{**specs.public(rid), "overlay": in_force.overlays.get(rid),
                       "pending": [c["number"] for c in pending if c["target"] == rid]} for rid in specs.SPECS],
            "pending_changes": len(pending), "exceptions_in_force": len(in_force.exceptions),
            "self_approval_allowed": single_admin(org_id),
            "note": "A core rule cannot be switched off. Severity can be raised freely and lowered only to the floor of the kind of data. "
                    "Every change needs a second person's approval and is recorded in the evidence chain."}


@router.get("/{org_id}/rules/changes")
async def list_changes(org_id: str, status: Optional[str] = Query(None), kind: Optional[str] = Query(None),
                       _user: User = Depends(check_org_access)):
    return {"changes": changes.list_changes(get_store(), org_id, status=status, kind=kind)}


@router.post("/{org_id}/rules/changes", status_code=201)
async def propose(org_id: str, body: ProposeBody, user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN))):
    c = _run(changes.propose, get_store(), org_id, body.kind, body.setting, user.username, body.reason, target=body.target)
    _audit(user, "RULE_CHANGE_PROPOSED", org_id, f"rule_change:{c['number']}", {"kind": c["kind"], "target": c["target"]})
    return c


@router.post("/{org_id}/rules/changes/{change_id}/approve")
async def approve(org_id: str, change_id: str, body: DecisionBody = DecisionBody(), user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN))):
    c = _run(changes.approve, get_store(), org_id, change_id, user.username, body.reason, single_admin(org_id))
    _audit(user, "RULE_CHANGE_APPROVED", org_id, f"rule_change:{c['number']}", {"self_approved": c["self_approved"], "target": c["target"]})
    return c


@router.post("/{org_id}/rules/changes/{change_id}/reject")
async def reject(org_id: str, change_id: str, body: DecisionBody = DecisionBody(), user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN))):
    c = _run(changes.reject, get_store(), org_id, change_id, user.username, body.reason)
    _audit(user, "RULE_CHANGE_REJECTED", org_id, f"rule_change:{c['number']}", {"target": c["target"]})
    return c


@router.post("/{org_id}/rules/changes/{change_id}/withdraw")
async def withdraw(org_id: str, change_id: str, body: DecisionBody = DecisionBody(), user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN))):
    c = _run(changes.withdraw, get_store(), org_id, change_id, user.username, body.reason)
    _audit(user, "RULE_CHANGE_WITHDRAWN", org_id, f"rule_change:{c['number']}", {"target": c["target"]})
    return c


@router.post("/{org_id}/rules/changes/{change_id}/revoke")
async def revoke(org_id: str, change_id: str, body: DecisionBody = DecisionBody(), user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN))):
    c = _run(changes.revoke, get_store(), org_id, change_id, user.username, body.reason)
    _audit(user, "RULE_EXCEPTION_REVOKED", org_id, f"rule_change:{c['number']}", {"target": c["target"]})
    return c


@router.get("/{org_id}/rules/exceptions")
async def exceptions(org_id: str, _user: User = Depends(check_org_access)):
    store = get_store()
    hits = changes.exception_hits(store, org_id)
    rows = changes.list_changes(store, org_id, status=changes.APPROVED, kind=changes.EXCEPTION)
    out = []
    for c in rows:
        n = hits.get(c["change_id"], 0)
        e = {**c, "findings_covered": n}
        if n == 0:
            e["note"] = ("No finding has matched this scope yet. Check the system and field names (they are compared ignoring case; "
                         "`*` matches anything).")
        out.append(e)
    return {"exceptions": out}


@router.get("/{org_id}/findings/{violation_id}/why")
async def why(org_id: str, violation_id: int, _user: User = Depends(check_org_access)):
    store = get_store()
    row = store.get_by_violation_id(org_id, violation_id)
    if row is None:
        raise HTTPException(404, "Finding not found.")
    rid = row.get("rule_id")
    t = trace.read(store, org_id, str(row.get("verdict_id")))
    spec = specs.public(rid) if rid in specs.SPECS else None
    if t is None:
        return {"recorded": False, "rule": spec, "note": "This finding was raised before the trace was kept, or its trace could not be written. "
                "The rule's conditions are shown without the answers."}
    return {"recorded": True, "rule": spec, "trace": t,
            "note": "Built when the finding was raised, from names, kinds of data and dates. It holds no value from the data. "
                    "Whether a finding is a breach of the Act is for the organization and its counsel."}
