"""
OpenTelemetry logs (phase F of docs/PS_ALIGNMENT_PLAN.md): OTLP/HTTP with a JSON body.

  POST /v1/{org}/otlp/logs     an ExportLogsServiceRequest as JSON      an agent's bearer token (as /events)

Each log record becomes an event exactly as if an agent had sent that line: the resource's `service.name` is the source system,
the body is the line, string attributes are the fields. Everything after that (detection, rules, incidents, the data map,
the lookup index) is the same code. OTLP over protobuf is not accepted (answered 415): configure the exporter for JSON.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request

from agent_store.models import Agent
from api.agent_auth import verify_agent_token
from api.integration import _process_event, _require_org_config
from labels import check_label
from schemas.models import Event, SourceType

logger = logging.getLogger("api.otlp")
router = APIRouter(prefix="/v1", tags=["otlp"])

MAX_BODY_BYTES = 1_000_000
MAX_RECORDS = 500


def _any_value(v: Any) -> Optional[str]:
    """A string from an OTLP AnyValue (string, number, bool, or a structure written out as JSON)."""
    if not isinstance(v, dict):
        return None
    for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if key in v:
            return str(v[key])
    if "arrayValue" in v or "kvlistValue" in v:
        return json.dumps(v, sort_keys=True)[:2000]
    return None


def _attrs(items: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for kv in items or []:
        if isinstance(kv, dict) and isinstance(kv.get("key"), str):
            val = _any_value(kv.get("value"))
            if val is not None:
                out[kv["key"]] = val
    return out


def _timestamp(rec: dict) -> datetime:
    try:
        ns = int(rec.get("timeUnixNano") or rec.get("observedTimeUnixNano") or 0)
        if ns > 0:
            return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    return datetime.now(timezone.utc)


@router.post("/{org_id}/otlp/logs")
async def otlp_logs(org_id: str, request: Request, _agent: Agent = Depends(verify_agent_token)) -> Dict[str, Any]:
    ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype != "application/json":
        raise HTTPException(415, "Send OTLP as JSON (Content-Type: application/json); OTLP over protobuf is not accepted.")
    _require_org_config(org_id)
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(413, f"The request is larger than {MAX_BODY_BYTES} bytes; send smaller batches.")
    try:
        doc = json.loads(raw)
    except ValueError:
        raise HTTPException(400, "The body is not valid JSON.")
    if not isinstance(doc, dict) or not isinstance(doc.get("resourceLogs", []), list):
        raise HTTPException(400, "Expected an OTLP ExportLogsServiceRequest with resourceLogs.")

    records: List[tuple] = []
    for rl in doc.get("resourceLogs", []):
        resource = _attrs((rl.get("resource") or {}).get("attributes")) if isinstance(rl, dict) else {}
        system = resource.get("service.name") or resource.get("service") or "otlp"
        for sl in (rl.get("scopeLogs") or []) if isinstance(rl, dict) else []:
            for rec in (sl.get("logRecords") or []) if isinstance(sl, dict) else []:
                if isinstance(rec, dict):
                    records.append((system, rec))
    if len(records) > MAX_RECORDS:
        raise HTTPException(413, f"At most {MAX_RECORDS} log records per request.")

    rejected, accepted = 0, 0
    for system, rec in records:
        try:
            body = _any_value(rec.get("body")) or ""
            attrs = _attrs(rec.get("attributes"))
            if not body.strip():
                body = json.dumps(attrs, sort_keys=True)[:2000] if attrs else ""
            if not body.strip():
                rejected += 1
                continue
            fields = {k[:200]: v[:10_000] for k, v in list(attrs.items())[:50]}
            for k in fields:
                check_label(k, "A field name")
            event = Event(tenant_id=org_id, event_id=uuid4(), source_type=SourceType.LOG, source_system=check_label(system[:200], "source_system"),
                          timestamp=_timestamp(rec), raw_snippet=body[:100_000], fields=fields)
        except (ValueError, TypeError):
            rejected += 1
            continue
        await _process_event(event, write_to_store=True, source_kind="otlp")
        accepted += 1
    out: Dict[str, Any] = {}
    if rejected:
        out["partialSuccess"] = {"rejectedLogRecords": rejected, "errorMessage": "some records had no body or an unusable name"}
    return out
