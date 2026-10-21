"""
Identifier lookup and rights requests (phase T6 of docs/TRUST_VISIBILITY_PLAN.md).

  POST /v1/{org}/subjects/lookup                       where an identifier was observed         COMPLIANCE_ADMIN, rate limited, audited
  POST /v1/{org}/requests                              open a rights request                     COMPLIANCE_ADMIN
  GET  /v1/{org}/requests, /requests/{id}              list and detail                           AUDITOR and above
  POST /v1/{org}/requests/{id}/tasks/{system}/confirm  an owner's confirmation                   COMPLIANCE_ADMIN
  POST /v1/{org}/requests/{id}/close                   close once every task is confirmed        COMPLIANCE_ADMIN
  GET  /v1/{org}/requests/{id}/record.pdf, record.json the signed record                         AUDITOR and above
  GET  /v1/{org}/subjects/keys                         key ids, purposes, dates (never keys)     AUDITOR and above
  POST /v1/{org}/subjects/keys/rotate, /retire         rotate or retire a key                    COMPLIANCE_ADMIN

The identifiers in a lookup or a new request are read from the body by hand and never echoed: not in an error, not in
the audit log (which stores a short token prefix), not in a log line. They are used in memory and dropped.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from api.auth_deps import get_current_user, org_access
from config_loader import OrgConfigNotFoundError, load_org_config
from evidence_store.store import get_store
from rate_limit import _limiter
from subject_lookup import keys as subject_keys, record as subject_record, rights
from subject_lookup.index import CATEGORIES, InvalidIdentifier
from user_store.models import User, UserRole

logger = logging.getLogger("api.subjects")
router = APIRouter(prefix="/v1", tags=["subjects"])

ADMIN = (UserRole.COMPLIANCE_ADMIN,)
READERS = (UserRole.AUDITOR, UserRole.COMPLIANCE_ADMIN)


def _audit(user: User, action: str, org: str, resource: str, detail: Dict[str, Any]) -> None:
    try:
        from audit_log.store import get_audit_store
        get_audit_store().log(action, actor_id=user.user_id, actor_name=user.username, org_id=org, resource=resource, detail=detail)
    except Exception:
        logger.debug("audit entry failed", exc_info=True)


async def _body(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "The request body must be JSON.")
    if not isinstance(body, dict):
        raise HTTPException(400, "The request body must be a JSON object.")
    return body


def _owners(org: str) -> Dict[str, dict]:
    try:
        return {k: v.model_dump() for k, v in (load_org_config(org).owners or {}).items()}
    except OrgConfigNotFoundError:
        return {}
    except Exception:
        return {}


def _identifiers(body: dict) -> List[tuple]:
    items = body.get("identifiers")
    if not isinstance(items, list):
        raise HTTPException(400, "identifiers must be a list of {category, identifier}.")
    out = []
    for it in items:
        if not isinstance(it, dict) or not isinstance(it.get("category"), str) or not isinstance(it.get("identifier"), str):
            raise HTTPException(400, "Each identifier needs a category and an identifier, both text.")
        out.append((it["category"], it["identifier"]))
    return out


# --------------------------------------------------------------------------- lookup

_admin_check = org_access(*ADMIN)     # a refusal is audited centrally (api/auth_deps.audit_denied), result DENIED


@router.post("/{org_id}/subjects/lookup")
async def lookup(org_id: str, request: Request, user: User = Depends(_admin_check)):
    _limiter.check("subject_lookup", user.user_id, max_requests=30, window_seconds=60)
    body = await _body(request)
    category, identifier = body.get("category"), body.get("identifier")
    if not isinstance(category, str) or not isinstance(identifier, str):
        raise HTTPException(400, "Give a category (" + ", ".join(CATEGORIES) + ") and an identifier, both text.")
    store = get_store()
    try:
        pairs = store.subjects.tokens_for_identifier(org_id, category, identifier)
    except InvalidIdentifier as e:
        _audit(user, "SUBJECT_LOOKUP", org_id, "subjects", {"category": category[:20], "result": "rejected"})
        raise HTTPException(400, str(e))
    del identifier
    result = store.subjects.lookup_tokens(org_id, category, pairs)
    prefix = pairs[0][1][:8] if pairs else ""
    _audit(user, "SUBJECT_LOOKUP", org_id, "subjects",
           {"category": category.lower(), "token_prefix": prefix, "systems": len(result["systems"])})
    return {**result, "token_prefix": prefix,
            "note": "Observed in these systems, in the logs Veritas received. This is not a statement about anywhere else."}


# --------------------------------------------------------------------------- requests

@router.post("/{org_id}/requests", status_code=201)
async def create_request(org_id: str, request: Request, user: User = Depends(org_access(*ADMIN))):
    body = await _body(request)
    ids = _identifiers(body)
    try:
        out = rights.create_request(get_store(), org_id, str(body.get("type", "")), str(body.get("requester_ref", "")), ids,
                                    owners=_owners(org_id), actor=user.username,
                                    received_at=body.get("received_at"), due_at=body.get("due_at"))
    except rights.RequestError as e:
        raise HTTPException(400, str(e))
    del ids
    _audit(user, "RIGHTS_REQUEST_CREATED", org_id, f"request:{out['request_id']}",
           {"type": out["type"], "tasks": len(out["tasks"])})
    return out


@router.get("/{org_id}/requests")
async def list_requests(org_id: str, status: Optional[str] = None, _user: User = Depends(org_access(*READERS))):
    return {"requests": rights.list_requests(get_store(), org_id, status=status),
            "response_days_configured": rights.response_days()}


def _get(org_id: str, request_id: str) -> dict:
    try:
        return rights.get_request(get_store(), org_id, request_id)
    except rights.RequestError as e:
        raise HTTPException(404, str(e))


@router.get("/{org_id}/requests/{request_id}")
async def get_request(org_id: str, request_id: str, _user: User = Depends(org_access(*READERS))):
    return _get(org_id, request_id)


@router.post("/{org_id}/requests/{request_id}/tasks/{system}/confirm")
async def confirm_task(org_id: str, request_id: str, system: str, request: Request,
                       user: User = Depends(org_access(*ADMIN))):
    try:
        note = (await request.json()).get("note") if request.headers.get("content-length") not in (None, "0") else None
    except Exception:
        note = None
    try:
        out = rights.confirm_task(get_store(), org_id, request_id, system, user.username, note if isinstance(note, str) else None)
    except rights.RequestError as e:
        raise HTTPException(400, str(e))
    _audit(user, "RIGHTS_TASK_CONFIRMED", org_id, f"request:{request_id}", {"system": system, "status": out["status"]})
    return out


@router.post("/{org_id}/requests/{request_id}/close")
async def close_request(org_id: str, request_id: str, request: Request, user: User = Depends(org_access(*ADMIN))):
    try:
        reason = (await request.json()).get("reason") if request.headers.get("content-length") not in (None, "0") else None
    except Exception:
        reason = None
    try:
        out = rights.close_request(get_store(), org_id, request_id, user.username, reason if isinstance(reason, str) else None)
    except rights.RequestError as e:
        raise HTTPException(400, str(e))
    _audit(user, "RIGHTS_REQUEST_CLOSED", org_id, f"request:{request_id}", {})
    return out


@router.get("/{org_id}/requests/{request_id}/record.json")
async def record_json(org_id: str, request_id: str, user: User = Depends(org_access(*READERS))):
    _get(org_id, request_id)
    body = subject_record.build(get_store(), org_id, request_id)
    _audit(user, "RIGHTS_RECORD_EXPORTED", org_id, f"request:{request_id}", {"format": "json"})
    return JSONResponse({"record": body, "signature": subject_record.sign(body)})


@router.get("/{org_id}/requests/{request_id}/record.pdf")
async def record_pdf(org_id: str, request_id: str, user: User = Depends(org_access(*READERS))):
    _get(org_id, request_id)
    body = subject_record.build(get_store(), org_id, request_id)
    data = subject_record.to_pdf(body, subject_record.sign(body))
    _audit(user, "RIGHTS_RECORD_EXPORTED", org_id, f"request:{request_id}", {"format": "pdf"})
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="rights-record-{request_id[:8]}.pdf"'})


# --------------------------------------------------------------------------- keys

@router.get("/{org_id}/subjects/keys")
async def list_keys(org_id: str, _user: User = Depends(org_access(*READERS))):
    return {"keys": get_store().keyring.listing(org_id)}


@router.post("/{org_id}/subjects/keys/rotate")
async def rotate_key(org_id: str, request: Request, user: User = Depends(org_access(*ADMIN))):
    purpose = (await _body(request)).get("purpose")
    if purpose not in subject_keys.PURPOSES:
        raise HTTPException(400, "purpose must be lookup or agent.")
    store = get_store()
    kid = store.keyring.rotate(org_id, purpose)
    store.subjects.forget_keys(org_id)
    _audit(user, "SUBJECT_KEY_ROTATED", org_id, f"key:{kid}", {"purpose": purpose})
    return {"key_id": kid, "purpose": purpose,
            "note": "Tokens made under older keys are still found. Agents receive a new agent key at their next heartbeat."}


@router.post("/{org_id}/subjects/keys/retire")
async def retire_key(org_id: str, request: Request, user: User = Depends(org_access(*ADMIN))):
    kid = (await _body(request)).get("key_id")
    if not isinstance(kid, str) or not kid:
        raise HTTPException(400, "Give the key_id to retire.")
    store = get_store()
    if not store.keyring.retire(org_id, kid):
        raise HTTPException(404, "No such active key.")
    store.subjects.forget_keys(org_id)
    _audit(user, "SUBJECT_KEY_RETIRED", org_id, f"key:{kid}", {})
    return {"retired": kid, "note": "Tokens made under this key can no longer be found."}
