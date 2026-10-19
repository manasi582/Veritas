"""
Veritas DPDPA Agent — Integration API Layer (Phase 5)
=========================================================
Three integration modes, ONE detection+rule-engine path underneath — no
logic duplication between them:

  A1. Stream/Telemetry mode  — POST /v1/{org_id}/events
      Generalizes what the v2 build's ingestion was: before this phase,
      there was no callable HTTP ingestion endpoint at all — Retail Co-
      simulated telemetry was pushed directly into an in-process
      asyncio.Queue by ingestion/log_generator.py and ingestion/
      api_generator.py (see run_pipeline.py), never via an HTTP route a
      real external system could call. This endpoint is genuinely new,
      not a generalization of a prior route — flagged explicitly since
      the plan assumed one already existed to relocate.

  A2. Synchronous scan API  — POST /v1/{org_id}/scan
      Stateless w.r.t. correctness: does not require any prior Stream-mode
      event to function. See ScanRequest/_event_from_scan_request for how
      an ad-hoc scan request becomes a well-formed Event.

  Both A1 and A2 funnel through the SAME `_process_event()` helper below,
  which calls the exact same detect_event() / evaluate_event() /
  EvidenceStore.append() functions Stream mode's run_pipeline.py has
  always used — untouched, per this phase's explicit "do not touch
  detection/rule-engine logic" instruction. Explanation is now
  build_deferred_explanation() (zero-cost template), not a per-verdict
  LLM call — see _process_event()'s docstring and llm_explainer/
  explainer.py's "AUTOMATIC EXPLANATION REMOVED" note.

  A3's CLI PoC (veritas_scan_cli.py, repo root) calls THIS module's /scan
  route over real HTTP — it does not import or reimplement anything here.

  Also: POST /v1/orgs/{org_id}/config — a minimal config-upload endpoint
  (explicit non-goal exception: Phase 5 depends on being able to register
  an org live during a demo, so a minimal version is in scope; no auth, no
  diffing, no rollback UI, exactly as instructed).

  Also: POST /v1/{org_id}/investigate — the "@N <question>" breach
  investigation endpoint. See investigation.py for the actual Q&A logic
  (context retrieval + grounded LLM call); this route is a thin adapter
  that parses the request shape and delegates.

WRITE-TO-EVIDENCE-STORE DECISION (Part A2.5, stated explicitly per the
plan's request): /scan WRITES to the Evidence Store whenever it produces a
violation verdict, exactly like Stream mode — "every violation lands in
the tamper-evident store for the auditor" applies regardless of which
integration mode found it. This is implemented identically for both
/events and /scan via the same _process_event() call (write_to_store=True
in both routes) — see Part B3's cross-check.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator

from agent_store.models import Agent
from api.agent_auth import verify_agent_token
from api.auth_deps import check_org_access, get_current_user, org_access, require_roles
from user_store.models import User, UserRole

from config_loader import OrgConfigNotFoundError, load_org_config
from dashboard.live_feed import publish as publish_live_feed
from detection.engine import identifier_validators
from detection.pool import RETRY_AFTER_SECONDS, PoolBusy, get_pool
from detection.models import DetectedEvent, MatchedEntity
from evidence_store.store import get_store
from investigation import investigate, parse_reference
import alerts
from incidents.template import template_of
from labels import check_label
from llm_explainer.explainer import ExplainedVerdict, build_deferred_explanation
from masking import mask_fields, mask_text
from org_config.store import (
    get_config_raw, get_config_version_meta,
    list_registered_orgs, upload_org_config as store_upload_org_config,
)
from registry.loader import reload_org_config
from rules.engine import evaluate_event
from schemas.models import Event, RuleId, SourceType, Verdict

logger = logging.getLogger("api.integration")

router = APIRouter(prefix="/v1", tags=["integration"])

# Sentinel source_system for scan requests that don't declare a real one.
# Never matches any org's actual registered source_system, so
# get_registry_entry() always misses for it — which is EXACTLY the
# "graceful degradation" the plan asks for (see module docstring on
# ScanRequest below): the existing, UNMODIFIED rule engine's Design
# Decision #2 (Check 2, rules/engine.py) already treats an unregistered
# field as a real PURPOSE_001 finding rather than crashing or fabricating
# a Retention verdict off a meaningless timestamp. No new rule-engine
# logic was written to achieve this — reusing what Phase 4 already built.
ADHOC_SCAN_SOURCE_SYSTEM = "adhoc_scan"


# ---------------------------------------------------------------------------
# Shared helper: org existence check
# ---------------------------------------------------------------------------

def _require_org_config(org_id: str):
    """
    Shared by every /v1/{org_id}/... route (Part A1's requirement,
    reused for A2 too since both need the identical check). Returns the
    loaded OrgConfig on success; raises a 404 with an actionable message
    on an unknown org_id — never lets an unknown org's events reach
    detection/the rule engine only to fail deeper in the pipeline.
    """
    try:
        return load_org_config(org_id)
    except OrgConfigNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=(
                f"org_id {org_id!r} has no registered config. "
                f"Register one first via POST /v1/orgs/{org_id}/config."
            ),
        )


# ---------------------------------------------------------------------------
# Shared engine call — used by BOTH /events and /scan
# ---------------------------------------------------------------------------

async def _process_event(event: Event, *, write_to_store: bool) -> Dict[str, Any]:
    """
    THE one shared path: detect -> evaluate -> (explain -> store -> live
    feed) per verdict. Both /events and /scan call this with their own
    synthesized Event and nothing else — this is what "one engine, three
    integration points" means concretely.

    NO AUTOMATIC LLM CALL: "explain" here is build_deferred_explanation()
    — a zero-cost deterministic template, not a real per-verdict LLM call.
    At real traffic volumes (thousands of violations), calling the LLM
    once per verdict automatically is an unbounded cost for explanation
    text that may never be read. The real, statute-grounded explanation
    now happens on demand, once per question, via investigation.py's
    "@N <question>" endpoint (POST /v1/{org_id}/investigate) — see that
    module. See llm_explainer/explainer.py's "AUTOMATIC EXPLANATION
    REMOVED" docstring note for the full rationale.
    """
    try:
        detected: DetectedEvent = await get_pool().detect(event, identifier_validators(event.tenant_id))
    except PoolBusy:
        raise HTTPException(
            status_code=503, headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
            detail="Veritas is busy detecting earlier events. Retry shortly; nothing was lost.",
        )
    verdicts: List[Verdict] = evaluate_event(detected)

    store = get_store() if write_to_store else None
    grouping = None
    if store is not None and verdicts:
        try:   # the line's template and root-cause hint, for grouping; a failure here only means "not grouped by wording"
            grouping = tuple(template_of(event.raw_snippet, detected.matched_entities))
        except Exception:
            logger.debug("template failed", exc_info=True)
    explained_and_stored: List[tuple[ExplainedVerdict, bool, Optional[int]]] = []

    for v in verdicts:
        explained = build_deferred_explanation(v)
        stored = False
        violation_id: Optional[int] = None
        if store is not None:
            try:
                store.append(explained, grouping=grouping)
                stored = True
                row = store.get_by_verdict_id(event.tenant_id, str(v.verdict_id))
                violation_id = row["violation_id"] if row else None
            except Exception as exc:
                logger.error("Failed to store verdict %s: %s", v.verdict_id, exc)
        explained_and_stored.append((explained, stored, violation_id))

        # Same live-feed payload shape run_pipeline.py's Stream-mode
        # broadcaster already builds (see dashboard/live_feed.py) — so a
        # /scan-detected verdict renders identically to a /events-detected
        # one in the dashboard's Live Feed (Part B3).
        await publish_live_feed({
            **explained.verdict.model_dump(mode="json"),
            "explanation": explained.explanation,
            "section_cited": explained.section_cited,
            "confidence": explained.confidence,
            "used_fallback": explained.used_fallback,
        })
        try:   # a person is told about serious findings; a broken channel must never stop ingest
            alerts.notify_finding(event.tenant_id, v.severity.value, v.rule_id.value, v.field, violation_id,
                                  v.breach_notification_candidate, v.source_system)
        except Exception:
            logger.debug("alert hand-over failed", exc_info=True)

    return {"detected": detected, "explained": explained_and_stored}


def _verdict_summary(explained: ExplainedVerdict, stored: bool, violation_id: Optional[int]) -> Dict[str, Any]:
    """
    JSON-safe verdict summary for API responses. Deliberately does NOT
    include any raw PII value — Verdict never carried raw matched text to
    begin with (only field NAMES, categories, and registry metadata), so
    this is safe to return/log as-is.

    violation_id is the per-tenant sequential number (see evidence_store/
    store.py) — None only if the write to the Evidence Store failed
    (stored=False), since that's the one thing that assigns it.
    """
    v = explained.verdict
    return {
        "verdict_id": str(v.verdict_id),
        "violation_id": violation_id,
        "rule_id": v.rule_id.value,
        "severity": v.severity.value,
        "field": v.field,
        "source_system": v.source_system,
        "breach_notification_candidate": v.breach_notification_candidate,
        "matched_registry_entry": v.matched_registry_entry,
        "explanation": explained.explanation,
        "section_cited": explained.section_cited,
        "stored_in_evidence_store": stored,
    }


def _entity_summary(m: MatchedEntity) -> Dict[str, Any]:
    """
    Entity summary WITHOUT matched_text — the whole point of this API
    (and the CLI built on top of it) is that raw PII never has to leave
    the response as cleartext for the caller to know what was found.
    """
    return {
        "field": m.field,
        "entity_type": m.entity_type,
        "confidence": m.confidence,
        "validation_status": m.validation_status,
    }


# ---------------------------------------------------------------------------
# A1 — Stream/Telemetry mode
# ---------------------------------------------------------------------------

class IngestEventRequest(BaseModel):
    source_type: SourceType
    source_system: str = Field(..., min_length=1, max_length=200)
    timestamp: Optional[datetime] = None
    raw_snippet: str = Field(..., min_length=1, max_length=100_000)
    fields: Dict[str, str] = Field(default_factory=dict)

    @field_validator("source_system")
    @classmethod
    def _source_system_is_plain(cls, v):
        return check_label(v, "source_system")

    @field_validator("source_type", mode="before")
    @classmethod
    def _source_type_case_insensitive(cls, v):
        """Accept "LOG"/"Log"/"log": the agent has historically sent upper case."""
        return v.strip().lower() if isinstance(v, str) else v

    @model_validator(mode="after")
    def _validate_fields_size(self) -> "IngestEventRequest":
        if len(self.fields) > 50:
            raise ValueError("Too many fields — max 50 per event.")
        for k, v in self.fields.items():
            if len(k) > 200:
                raise ValueError(f"Field key too long (max 200 chars): {repr(k)[:40]}")
            check_label(k, "A field name")
            if len(v) > 10_000:
                raise ValueError(f"Field value for {k!r} too long (max 10,000 chars).")
        return self


@router.post("/{org_id}/events")
async def ingest_event(
    org_id: str,
    req: IngestEventRequest,
    _agent: Agent = Depends(verify_agent_token),
) -> Dict[str, Any]:
    """
    Stream/Telemetry mode. org_id comes ONLY from the URL path — never
    inferred from any default/config/global — and is what gets threaded
    into the synthesized Event's tenant_id, and from there into every
    downstream check, the Evidence Store write, and the live-feed
    broadcast room.
    """
    _require_org_config(org_id)

    event = Event(
        tenant_id=org_id,
        event_id=uuid4(),
        source_type=req.source_type,
        source_system=req.source_system,
        timestamp=req.timestamp or datetime.now(timezone.utc),
        raw_snippet=req.raw_snippet,
        fields=req.fields,
    )
    result = await _process_event(event, write_to_store=True)
    detected: DetectedEvent = result["detected"]

    return {
        "org_id": org_id,
        "event_id": str(event.event_id),
        "contains_pii": detected.contains_pii,
        "entities": [_entity_summary(m) for m in detected.matched_entities],
        "verdicts": [_verdict_summary(ev, stored, vid) for ev, stored, vid in result["explained"]],
    }


# ---------------------------------------------------------------------------
# A2 — Synchronous scan API
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """
    Accepts `text` (unstructured — e.g. a pasted log line), `fields`
    (structured — matching the org's declared field names), or both.

    PRECEDENCE WHEN BOTH ARE GIVEN (documented per the plan's explicit
    request): both are processed and results are merged — detection runs
    over `fields` AND over `text`, deduplicated exactly the way Phase 3's
    detect_event() already deduplicates a structured field's value against
    its own serialized appearance in raw_snippet (see detection/engine.py).
    No new dedup logic was written for this — the existing engine already
    does the right thing when given both a `fields` dict and a `raw_snippet`
    string, which is exactly what this endpoint constructs.

    source_type CHOICE WHEN BOTH ARE GIVEN: `fields` presence means API
    (SourceType.API) even if `text` is also present — text-only means LOG
    (SourceType.LOG). Rationale: SourceType.LOG unconditionally satisfies
    Check 1 (Exposure) for EVERY match in the event, per the rule engine's
    own design (see rules/engine.py) — that's the right call for a bare
    pasted log line (the whole point of the log-exposure rule), but would
    be a surprising, overly aggressive side effect if it ALSO applied to
    legitimately-declared `fields` just because the caller happened to
    also paste an accompanying text blob in the same request.
    """
    text: Optional[str] = None
    fields: Optional[Dict[str, str]] = None
    source_system: Optional[str] = None

    @model_validator(mode="after")
    def _require_at_least_one_input(self) -> "ScanRequest":
        if not self.text and not self.fields:
            raise ValueError("At least one of 'text' or 'fields' must be provided.")
        if self.source_system:
            check_label(self.source_system, "source_system")
        for k in (self.fields or {}):
            check_label(k, "A field name")
        return self


def _event_from_scan_request(org_id: str, req: ScanRequest) -> Event:
    fields = req.fields or {}
    only_text = bool(req.text) and not fields
    if req.text:
        raw_snippet = req.text
    else:
        # No text at all: raw_snippet must still be non-empty (Event's
        # schema requires it) — serialize fields, matching the existing
        # convention that API-sourced raw_snippet holds the JSON payload
        # (see detection/engine.py's module docstring on this exact point).
        raw_snippet = json.dumps(fields)

    return Event(
        tenant_id=org_id,
        event_id=uuid4(),
        source_type=SourceType.LOG if only_text else SourceType.API,
        source_system=req.source_system or ADHOC_SCAN_SOURCE_SYSTEM,
        timestamp=datetime.now(timezone.utc),
        raw_snippet=raw_snippet,
        fields=fields,
    )


@router.post("/{org_id}/scan")
async def scan(
    org_id: str, req: ScanRequest,
    _user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN, UserRole.AUDITOR)),
) -> Dict[str, Any]:
    """
    Synchronous scan — stateless w.r.t. correctness (no prior Stream-mode
    event required). See module docstring for the write-to-Evidence-Store
    decision (yes, same as Stream mode) and ScanRequest's docstring for the
    text+fields precedence rule.

    GRACEFUL DEGRADATION (Part A2.4): a scan request with no declared/
    recognized `source_system` gets ADHOC_SCAN_SOURCE_SYSTEM, which never
    matches any org's registry — every field is then correctly treated as
    "unregistered" by the UNCHANGED rule engine (Design Decision #2, Check
    2): it produces a real PURPOSE_001 finding rather than either crashing
    or fabricating a false RETENTION_001 off an age that has no real
    meaning for a bare pasted value. If the caller DOES pass a real
    `source_system` matching their own org's config, Checks 2/3 resolve
    against real registry entries exactly as they would for Stream mode.
    """
    _require_org_config(org_id)

    event = _event_from_scan_request(org_id, req)
    result = await _process_event(event, write_to_store=True)
    detected: DetectedEvent = result["detected"]
    explained_and_stored = result["explained"]

    all_matches = detected.matched_entities
    verdict_summaries = [_verdict_summary(ev, stored, vid) for ev, stored, vid in explained_and_stored]
    linkage_risks = [
        s for s, (ev, _, _) in zip(verdict_summaries, explained_and_stored)
        if ev.verdict.rule_id == RuleId.LINKAGE_001
    ]

    response: Dict[str, Any] = {
        "org_id": org_id,
        "event_id": str(event.event_id),
        "contains_pii": detected.contains_pii,
        "entities": [_entity_summary(m) for m in all_matches],
        "linkage_risks": linkage_risks,
        "verdicts": verdict_summaries,
    }
    if req.text is not None:
        response["masked_text"] = mask_text(req.text, all_matches)
    if req.fields:
        response["masked_fields"] = mask_fields(req.fields, all_matches)
    return response


# ---------------------------------------------------------------------------
# Org listing (powers the dashboard's org-selector — Part B2)
# ---------------------------------------------------------------------------

@router.get("/orgs")
async def list_orgs(_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Every org_id with at least one stored config version. Read-only,
    no auth — same posture as the rest of this phase (see module docstring
    on the auth non-goal)."""
    return {"org_ids": list_registered_orgs()}


# ---------------------------------------------------------------------------
# Phase 14 — Policy Management: read current config + version history
# ---------------------------------------------------------------------------

@router.get("/orgs/{org_id}/config")
async def get_org_config_endpoint(
    org_id: str, _user: User = Depends(org_access()),
) -> Dict[str, Any]:
    """Get the current compliance policy config for an org."""
    _require_org_config(org_id)
    raw = get_config_raw(org_id)
    if raw is None:
        raise HTTPException(status_code=404, detail=f"No config found for org {org_id!r}.")
    return raw


@router.get("/orgs/{org_id}/config/history")
async def list_config_versions(
    org_id: str, _user: User = Depends(org_access()),
) -> Dict[str, Any]:
    """
    List all policy config versions for an org, newest first.
    Each entry includes: version filename, upload timestamp, whether it's current, size.
    """
    _require_org_config(org_id)
    versions = get_config_version_meta(org_id)
    return {"org_id": org_id, "versions": versions, "total": len(versions)}


@router.get("/orgs/{org_id}/config/history/{version}")
async def get_config_version(
    org_id: str, version: str, _user: User = Depends(org_access()),
) -> Dict[str, Any]:
    """
    Retrieve a specific historical version of an org's compliance policy.
    Version is the filename e.g. '2026-08-21T00-00-00Z.yaml'.
    """
    _require_org_config(org_id)
    raw = get_config_raw(org_id, version=version)
    if raw is None:
        raise HTTPException(status_code=404, detail=f"Version {version!r} not found for org {org_id!r}.")
    versions = get_config_version_meta(org_id)
    is_current = any(v["version"] == version and v["is_current"] for v in versions)
    return {"version": version, "is_current": is_current, "config": raw}


# ---------------------------------------------------------------------------
# Minimal org config upload (explicit non-goal exception — see module docstring)
# ---------------------------------------------------------------------------

@router.post("/orgs/{org_id}/config")
async def upload_org_config_endpoint(
    org_id: str, config: Dict[str, Any] = Body(...),
    _user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN)),
) -> Dict[str, Any]:
    """
    Minimal config registration: validates via Phase 1's own
    validate_org_config (called internally by org_config.store.
    upload_org_config), stores it if valid, and returns success/errors.
    No auth, no diffing, no rollback UI — exactly as scoped.

    On success, immediately busts registry.loader's in-memory config cache
    for this org_id (reload_org_config) so the NEXT request against this
    org_id — /v1/{org_id}/events or /v1/{org_id}/scan — sees the new/
    updated config with no server restart, which is the whole point of
    supporting live org registration during a demo.
    """
    result = store_upload_org_config(org_id, config)
    if result["status"] == "ok":
        reload_org_config(org_id)
        logger.info("Registered/updated org config for org_id=%r, reloaded into rule engine cache.", org_id)
        # Auto-grant the uploading user access to this org (SUPER_ADMIN already has wildcard)
        if _user.role != UserRole.SUPER_ADMIN:
            try:
                from user_store.store import get_user_store as _users
                _users().grant_org_access(_user.user_id, org_id, granted_by=_user.user_id)
                logger.info("Auto-granted %r access to org %r after config upload.", _user.username, org_id)
            except Exception:
                pass
        # Audit log the policy change
        try:
            from audit_log.store import get_audit_store
            get_audit_store().log(
                "ORG_CONFIG_UPDATED",
                actor_id=_user.user_id, actor_name=_user.username,
                org_id=org_id, resource=f"org_config:{result.get('version','unknown')}",
            )
        except Exception:
            pass
    return result


# ---------------------------------------------------------------------------
# Breach investigation — "@N <question>" (see investigation.py)
# ---------------------------------------------------------------------------

class InvestigateRequest(BaseModel):
    """
    Two equivalent ways to ask:
      - `text`: the raw utterance exactly as an auditor would type it,
        e.g. "@01 What exactly is the breach here?" — the '@N' reference
        is parsed out of it server-side (investigation.parse_reference).
      - `violation_id` + `question`: the same thing, already split, for
        programmatic callers that already know the number.
    `history`: optional prior turns for this SAME violation's thread —
    [{"role": "user"|"assistant", "content": "..."}, ...] — the caller
    (e.g. the dashboard) re-sends this every call; the server itself is
    stateless (see investigation.py's module docstring for why).
    """
    text: Optional[str] = None
    violation_id: Optional[int] = None
    question: Optional[str] = None
    history: List[Dict[str, str]] = Field(default_factory=list)


@router.post("/{org_id}/investigate")
async def investigate_endpoint(
    org_id: str, req: InvestigateRequest,
    _user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN, UserRole.AUDITOR)),
) -> Dict[str, Any]:
    """
    Layer 2+3 of the breach investigation system: resolve the '@N'
    reference to its full stored breach record, then answer the
    auditor's question grounded in that record. See investigation.py for
    the actual retrieval/LLM/guardrail logic — this route only adapts
    the two accepted request shapes and validates org_id exists.
    """
    _require_org_config(org_id)

    if req.text:
        violation_id, question = parse_reference(req.text)
        if violation_id is None:
            raise HTTPException(
                status_code=400,
                detail="No '@N' violation reference found in 'text' (e.g. '@01 what happened?').",
            )
    elif req.violation_id is not None and req.question:
        violation_id, question = req.violation_id, req.question
    else:
        raise HTTPException(
            status_code=400,
            detail="Provide either 'text' (e.g. '@01 what happened?') or both 'violation_id' and 'question'.",
        )

    result = investigate(org_id, violation_id, question, history=req.history)
    return result.model_dump()
