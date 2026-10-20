"""
DPDPA Compliance Agent — Dashboard Server (Phase 7, multi-tenant since Phase 5+6)
====================================================================================
FastAPI server providing:
  - GET /                          — serves the dashboard HTML
  - WebSocket /ws/{org_id}         — live feed of ExplainedVerdicts for ONE org
  - GET /api/{org_id}/verdicts     — Evidence Store query, scoped to org_id
  - GET /api/{org_id}/verdicts/{verdict_id} — single verdict detail, scoped
  - POST /api/{org_id}/verdicts/{verdict_id}/status — update remediation_status, scoped
  - GET /api/{org_id}/verify-chain — run verify_chain(org_id) and return result
  - GET /api/{org_id}/stats        — summary counts, scoped to org_id
  - PLUS everything mounted from api/integration.py (Phase 5): POST
    /v1/{org_id}/events, POST /v1/{org_id}/scan, POST /v1/orgs/{org_id}/config

PHASE 6 CHANGE — every one of the dashboard's own routes above now takes
org_id as a required path parameter and scopes its EvidenceStore call
accordingly (see evidence_store/store.py's own Phase 6 doc comment: every
read method there now REQUIRES tenant_id). Before this phase, none of
these routes took any org_id at all — GET /api/verdicts queried across
every tenant's data unconditionally, and GET /ws broadcast every org's
verdicts to every connected client. Both were real cross-tenant leaks;
both are fixed here. See dashboard/live_feed.py for the WebSocket-room fix.

The dashboard has no authentication/session model of any kind (checked
before choosing an approach, per the plan's instruction) — so tenant
scoping here is done via an explicit org_id in the URL, matched by a
dropdown/org-selector in the front-end (index.html), not by any inferred
identity. Real auth is flagged as a demo-readiness gap in the phase
report, not built here (explicit non-goal).

Run with:
    python -m dashboard.server
    python -m dashboard.server --port 8080

Or from the pipeline (run_pipeline.py) which starts it programmatically.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
from typing import Any, Optional

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from api.auth import needs_setup, router as auth_router
from api.auth_deps import check_org_access, get_current_user, org_access, require_roles
from api.integration import router as integration_router
from dashboard.live_feed import broadcaster_task, get_live_feed_queue, register_client, set_server_loop, unregister_client
from evidence_store.store import get_store
from license import LicenseError, validate_license
from user_store.models import User, UserRole

logger = logging.getLogger("dashboard.server")

# ---------------------------------------------------------------------------
# Body size limit middleware (Block 8 — Security Hardening)
# Rejects requests whose Content-Length header exceeds 256 KB before the
# body is read. Prevents unbounded memory use from oversized Agent payloads.
# ---------------------------------------------------------------------------

from veritas_version import MIN_AGENT_VERSION, get_version

_API_VERSION = "1.0.0"
_MAX_BODY_BYTES = 256 * 1024  # 256 KB


class _BodySizeLimit(BaseHTTPMiddleware):
    """Rejects requests whose Content-Length exceeds 256 KB (Phase 8 hardening)."""
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > _MAX_BODY_BYTES:
                    return JSONResponse(
                        {"detail": f"Request body too large. Maximum {_MAX_BODY_BYTES} bytes."},
                        status_code=413,
                    )
            except ValueError:
                pass
        return await call_next(request)


class _SecurityHeaders(BaseHTTPMiddleware):
    """
    Phase 21 — Security headers added to every response.

    CSP notes:
      - 'unsafe-inline' is required because the dashboard uses inline JS/CSS.
        This is a known limitation of single-file HTML dashboards.
        Future hardening would extract JS to separate files and add nonces.
      - frame-ancestors 'none' prevents clickjacking (supersedes X-Frame-Options
        in modern browsers; both are set for compatibility).
      - connect-src includes wss: for WebSocket connections.
    """

    def _csp(self, is_https: bool) -> str:
        upgrade = "upgrade-insecure-requests; " if is_https else ""
        return (
            f"{upgrade}"
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        is_https = request.url.scheme == "https"

        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]            = "DENY"
        response.headers["X-XSS-Protection"]           = "1; mode=block"
        response.headers["Referrer-Policy"]             = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"]     = self._csp(is_https)
        response.headers["Permissions-Policy"]          = "geolocation=(), camera=(), microphone=()"
        response.headers["X-Veritas-API-Version"]       = _API_VERSION

        if is_https:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Never expose server implementation details
        for hdr in ("server", "x-powered-by"):
            try:
                del response.headers[hdr]
            except (KeyError, Exception):
                pass

        return response


app = FastAPI(
    title="Veritas DPDPA Compliance Platform",
    version=_API_VERSION,
    description=(
        "On-premise DPDPA compliance monitoring API. "
        "All endpoints require authentication except /health, /ready, "
        "/login, /setup, and /api/tls/cert."
    ),
    docs_url=None,     # Disable auto-generated Swagger UI in production
    redoc_url=None,    # Disable ReDoc in production
    openapi_url=None,  # served by openapi_schema() below so that it requires a login
)

app.add_middleware(_SecurityHeaders)
app.add_middleware(_BodySizeLimit)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000",
                   "https://localhost:8000", "https://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["X-Veritas-API-Version"],
)

# Serve bundled JS libraries (jsPDF etc.) at /static — no CDN needed
# Works offline / air-gapped. Path resolves to dashboard/static/ directory.
_static_dir = None
try:
    from runtime_paths import bundle_root
    _static_dir = bundle_root() / "dashboard" / "static"
    if not _static_dir.exists():
        # Development fallback: next to this file
        from pathlib import Path as _Path
        _static_dir = _Path(__file__).parent / "static"
except Exception:
    from pathlib import Path as _Path
    _static_dir = _Path(__file__).parent / "static"

if _static_dir and _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

# Auth router first — login/logout/setup are public
app.include_router(auth_router)

app.include_router(integration_router)

from api.agents import router as agents_router  # noqa: E402
app.include_router(agents_router)
from api.anchors import router as anchors_router  # noqa: E402
app.include_router(anchors_router)
from api.incidents import router as incidents_router  # noqa: E402
app.include_router(incidents_router)
from api.flows import router as flows_router  # noqa: E402
app.include_router(flows_router)
from api.subjects import router as subjects_router  # noqa: E402
app.include_router(subjects_router)


# ---------------------------------------------------------------------------
# Routes — dashboard page + WebSocket
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def serve_login():
    from runtime_paths import bundle_root
    html_path = bundle_root() / "dashboard" / "login.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.get("/setup", response_class=HTMLResponse)
async def serve_setup():
    """First-boot admin setup page. Redirects to login if users already exist."""
    from fastapi.responses import RedirectResponse
    if not needs_setup():
        return RedirectResponse(url="/login", status_code=302)
    from runtime_paths import bundle_root
    html_path = bundle_root() / "dashboard" / "setup.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    from fastapi.responses import RedirectResponse
    from runtime_paths import bundle_root
    from api.auth_deps import decode_access_token, _COOKIE_NAME

    # First-boot: no users exist → redirect to setup
    if needs_setup():
        return RedirectResponse(url="/setup", status_code=302)

    # Not authenticated → redirect to login
    token = request.cookies.get(_COOKIE_NAME)
    if not token or not decode_access_token(token):
        return RedirectResponse(url="/login", status_code=302)

    html_path = bundle_root() / "dashboard" / "index.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.websocket("/ws/{org_id}")
async def websocket_endpoint(ws: WebSocket, org_id: str):
    """
    Live feed for exactly ONE org's verdicts.
    Auth: validates the session cookie on the WebSocket upgrade handshake and that the
    user may access this organization. Closes with 4001 if not authenticated and 4003
    if the account is disabled or has no access to the organization.
    """
    from fastapi import HTTPException
    from api.auth_deps import _COOKIE_NAME, can_access_org, user_from_token
    try:
        # Same rules as the HTTP API: a valid session of an active account...
        ws_user = user_from_token(ws.cookies.get(_COOKIE_NAME))
    except HTTPException as exc:
        await ws.close(code=4001 if exc.status_code == 401 else 4003, reason="Authentication required")
        return
    if ws_user.must_change_password:
        await ws.close(code=4003, reason="Password change required")
        return
    # ...that belongs to THIS organization. Without this any logged-in user could watch
    # another organization's live violations.
    if not can_access_org(ws_user, org_id):
        await ws.close(code=4003, reason="No access to this organisation")
        return

    await ws.accept()
    register_client(org_id, ws)
    logger.info("WebSocket client connected for org_id=%r.", org_id)
    try:
        while True:
            # Keep connection alive; data flows from broadcaster_task via publish().
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        unregister_client(org_id, ws)
        logger.info("WebSocket client disconnected for org_id=%r.", org_id)


# ---------------------------------------------------------------------------
# Routes — Evidence Store queries, all org_id-scoped
# ---------------------------------------------------------------------------

from fastapi import Depends  # noqa: E402 (needed here for Depends in route signatures)

@app.get("/api/{org_id}/verdicts")
async def list_verdicts(
    org_id: str,
    source_system: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    remediation_status: Optional[str] = Query(None),
    date_start: Optional[str] = Query(None),
    date_end: Optional[str] = Query(None),
    _user: User = Depends(check_org_access),
):
    store = get_store()
    date_range = (date_start, date_end) if date_start and date_end else None
    rows = store.query(
        org_id,
        date_range=date_range,
        source_system=source_system,
        severity=severity,
        remediation_status=remediation_status,
    )
    return {"verdicts": rows, "count": len(rows)}


@app.get("/api/{org_id}/verdicts/{verdict_id}")
async def get_verdict(org_id: str, verdict_id: str, _user: User = Depends(check_org_access)):
    store = get_store()
    row = store.get_by_verdict_id(org_id, verdict_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Verdict {verdict_id!r} not found for org_id {org_id!r}")
    return row


@app.get("/api/{org_id}/violations/{violation_id}")
async def get_violation_by_number(org_id: str, violation_id: int, _user: User = Depends(check_org_access)):
    """
    The "tag #N and ask what the breach is" lookup — a plain,
    human-referenceable per-tenant sequential number (1, 2, 3, ...) rather
    than the full verdict_id UUID. Returns the same row shape as
    GET /api/{org_id}/verdicts/{verdict_id}, already carrying the stored,
    grounding-checked `explanation`/`section_cited` from detection time —
    no new LLM call happens on lookup, it's a direct evidence-store read.
    """
    store = get_store()
    row = store.get_by_violation_id(org_id, violation_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Violation #{violation_id} not found for org_id {org_id!r}")
    return row


class StatusUpdate(BaseModel):
    status: str


@app.post("/api/{org_id}/verdicts/{verdict_id}/status")
async def update_verdict_status(
    org_id: str, verdict_id: str, body: StatusUpdate,
    _user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN)),
):
    store = get_store()
    try:
        store.update_status(org_id, verdict_id, body.status, actor=_user.username)
        row = store.get_by_verdict_id(org_id, verdict_id)
        try:
            from audit_log.store import AuditAction, get_audit_store
            _action = AuditAction.VIOLATION_ACKNOWLEDGED if body.status == "ACKNOWLEDGED" else AuditAction.VIOLATION_RESOLVED
            get_audit_store().log(_action, actor_id=_user.user_id, actor_name=_user.username,
                                  org_id=org_id, resource=f"verdict:{verdict_id}")
        except Exception:
            pass
        return {"ok": True, "verdict": row}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/{org_id}/verify-chain")
async def verify_chain(org_id: str, _user: User = Depends(check_org_access)):
    """
    Verify the tamper-evident SHA-256 hash chain for this organisation's evidence.
    Returns whether the chain is intact and where it first breaks (if at all).

    Terminology note: the evidence store is TAMPER-EVIDENT, not tamper-proof.
    It can detect modification but cannot prevent it — the chain verification
    result should be treated as a signal, not a guarantee.
    """
    store = get_store()
    result = store.verify_chain(org_id)
    total = store.count(org_id)
    return {
        **result,
        "total_records": total,
        "terminology": "tamper-evident",
        "note": (
            "VERIFIED means all stored records match their SHA-256 chain hashes. "
            "BROKEN means at least one record was modified, deleted, or reordered after storage."
        ),
    }


@app.get("/api/{org_id}/evidence/export")
async def export_evidence(
    org_id: str,
    format: str = Query("json", pattern="^(json|csv)$"),
    source_system: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    remediation_status: Optional[str] = Query(None),
    _user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN, UserRole.AUDITOR)),
):
    """
    Export evidence records as JSON or CSV.
    Requires COMPLIANCE_ADMIN or AUDITOR role.
    Raw PII values are never included — only verdict metadata.
    """
    import csv
    import io
    from fastapi.responses import StreamingResponse

    store = get_store()
    rows = store.query(org_id, source_system=source_system, severity=severity,
                       remediation_status=remediation_status)

    try:
        from audit_log.store import get_audit_store
        get_audit_store().log("REPORT_EXPORTED", actor_id=_user.user_id, actor_name=_user.username,
                              org_id=org_id, detail={"format": format, "count": len(rows)})
    except Exception:
        pass

    if format == "csv":
        fields = ["violation_id", "verdict_id", "rule_id", "severity", "field",
                  "source_system", "remediation_status", "timestamp", "breach_notification_candidate"]
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=veritas-evidence-{org_id}.csv"},
        )
    else:
        import json as _json
        content = _json.dumps({"org_id": org_id, "count": len(rows), "records": rows}, default=str, indent=2)
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=veritas-evidence-{org_id}.json"},
        )


@app.get("/api/{org_id}/stats")
async def get_stats(org_id: str, _user: User = Depends(check_org_access)):
    return get_store().stats(org_id)       # counted by the database: no record is decrypted


# ---------------------------------------------------------------------------
# TLS certificate endpoint (public — Agents need this to verify the server)
# ---------------------------------------------------------------------------

@app.get("/api/tls/cert")
async def get_server_cert():
    """
    Returns the server's TLS certificate in PEM format.
    Public endpoint — no auth required. Agents call this during enrollment
    to obtain the CA cert they need to verify future TLS connections.
    Only available when TLS is enabled (returns 404 when running over HTTP).
    """
    from fastapi.responses import PlainTextResponse
    from tls import cert_path, tls_mode
    if tls_mode() == "false":
        raise HTTPException(status_code=404, detail="TLS is not enabled on this server.")
    crt = cert_path()
    if not crt.exists():
        raise HTTPException(status_code=404, detail="TLS certificate not yet generated.")
    return PlainTextResponse(crt.read_text(encoding="utf-8"), media_type="application/x-pem-file")


# ---------------------------------------------------------------------------
# Case Management (Phase 13)
# ---------------------------------------------------------------------------

class CaseUpdate(BaseModel):
    assignee: Optional[str] = None
    priority: Optional[str] = None
    due_date: Optional[str] = None
    notes:    Optional[str] = None


class CommentCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=4000)


@app.get("/api/{org_id}/verdicts/{verdict_id}/case")
async def get_case(org_id: str, verdict_id: str, _user: User = Depends(check_org_access)):
    store = get_store()
    return store.get_case(org_id, verdict_id) or {"verdict_id": verdict_id, "tenant_id": org_id}


@app.patch("/api/{org_id}/verdicts/{verdict_id}/case")
async def update_case(
    org_id: str, verdict_id: str, body: CaseUpdate,
    _user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN)),
):
    store = get_store()
    if store.get_by_verdict_id(org_id, verdict_id) is None:
        raise HTTPException(404, f"Verdict {verdict_id!r} not found.")
    result = store.upsert_case(org_id, verdict_id, assignee=body.assignee,
                               priority=body.priority, due_date=body.due_date,
                               notes=body.notes, updated_by=_user.username)
    return result


@app.get("/api/{org_id}/verdicts/{verdict_id}/comments")
async def get_comments(org_id: str, verdict_id: str, _user: User = Depends(check_org_access)):
    return {"comments": get_store().get_comments(org_id, verdict_id)}


@app.post("/api/{org_id}/verdicts/{verdict_id}/comments", status_code=201)
async def add_comment(
    org_id: str, verdict_id: str, body: CommentCreate,
    _user: User = Depends(org_access(UserRole.COMPLIANCE_ADMIN, UserRole.AUDITOR)),
):
    store = get_store()
    if store.get_by_verdict_id(org_id, verdict_id) is None:
        raise HTTPException(404, f"Verdict {verdict_id!r} not found.")
    return store.add_comment(org_id, verdict_id, body.content,
                             author_id=_user.user_id, author_name=_user.username)


# ---------------------------------------------------------------------------
# Audit log endpoint (SUPER_ADMIN only)
# ---------------------------------------------------------------------------

@app.get("/api/audit/logs")
async def get_audit_logs(
    action: Optional[str] = Query(None),
    actor_id: Optional[str] = Query(None),
    org_id: Optional[str] = Query(None),
    result: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _user: User = Depends(require_roles(UserRole.SUPER_ADMIN)),
):
    """Return audit log entries. SUPER_ADMIN only."""
    from audit_log.store import get_audit_store
    store = get_audit_store()
    entries = store.query(action=action, actor_id=actor_id, org_id=org_id, result=result, limit=limit, offset=offset)
    total = store.count(action=action, org_id=org_id)
    return {"entries": entries, "total": total, "limit": limit, "offset": offset}


# ---------------------------------------------------------------------------
# Backup & Recovery endpoints (Phase 18) — SUPER_ADMIN only
# ---------------------------------------------------------------------------

@app.get("/api/system/backups")
async def list_backups_endpoint(_user: User = Depends(require_roles(UserRole.SUPER_ADMIN))):
    """List available backup files. SUPER_ADMIN only."""
    from backup import list_backups
    return {"backups": list_backups()}


@app.post("/api/system/backup", status_code=201)
async def create_backup_endpoint(_user: User = Depends(require_roles(UserRole.SUPER_ADMIN))):
    """
    Trigger a backup of all Veritas data.
    Backup is verified immediately after creation.
    SUPER_ADMIN only. Stop agents before restoring from a backup.
    """
    from backup import create_backup
    try:
        out = create_backup()
        size_mb = round(out.stat().st_size / 1_048_576, 1)
        try:
            from audit_log.store import get_audit_store
            get_audit_store().log("BACKUP_CREATED", actor_id=_user.user_id,
                                  actor_name=_user.username,
                                  detail={"filename": out.name, "size_mb": size_mb})
        except Exception:
            pass
        return {"ok": True, "filename": out.name, "size_mb": size_mb, "path": str(out)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Backup failed: {e}")


@app.post("/api/system/backup/verify")
async def verify_backup_endpoint(
    filename: str = Query(..., description="Backup filename to verify"),
    _user: User = Depends(require_roles(UserRole.SUPER_ADMIN)),
):
    """Verify a backup archive's integrity by checking SHA-256 checksums."""
    from backup import list_backups, verify_backup
    from runtime_paths import data_root
    # a file name, not a path: otherwise "../secrets/db.key" would read (and reveal the existence of)
    # any file the service can reach
    if not filename or filename != Path(filename).name or filename in (".", ".."):
        raise HTTPException(status_code=400, detail="Give the backup's file name, as listed by `veritas backups`.")
    backup_path = data_root() / "backups" / filename
    if not backup_path.exists():
        raise HTTPException(status_code=404, detail=f"Backup {filename!r} not found.")
    ok, errors = verify_backup(backup_path)
    return {"verified": ok, "filename": filename, "errors": errors}


# ---------------------------------------------------------------------------
# Health & Readiness endpoints (public — for load balancers / monitoring)
# ---------------------------------------------------------------------------

@app.get("/api/version")
async def api_version():
    """
    Public endpoint: the API version only. The list of endpoints is in the API schema,
    which requires a login (GET /api/openapi.json).
    """
    return {"api_version": _API_VERSION, "service": "veritas"}


@app.get("/api/openapi.json", include_in_schema=False)
async def openapi_schema(_user: User = Depends(get_current_user)):
    """The full API schema, for integrations. Requires a login."""
    return app.openapi()


@app.get("/health")
async def health():
    """
    Liveness probe — returns 200 if the server process is running.
    Does NOT check dependencies. Used by: load balancers, systemd, Docker.
    """
    return {"status": "ok", "service": "veritas", "version": _API_VERSION}   # API version, not the release


@app.get("/metrics", include_in_schema=True)
async def metrics_endpoint(request: Request):
    """
    Prometheus-format metrics for the customer's monitoring. Authenticated by VERITAS_METRICS_TOKEN
    (a bearer token chosen by the administrator), not by a user session. Off, and answering 401 to
    everyone, unless that setting exists.
    """
    import metrics as _metrics
    from fastapi.responses import PlainTextResponse
    if not _metrics.token_ok(request.headers.get("authorization")):
        raise HTTPException(status_code=401, detail="Authentication required.")
    return PlainTextResponse(_metrics.render(), media_type="text/plain; version=0.0.4")


@app.get("/ready")
async def ready():
    """
    Readiness probe: 200 if the server can serve requests, 503 if a critical dependency is
    unavailable. Public (load balancers, Kubernetes), so it reports only ok/error per check;
    the reasons are logged on the server and shown, to logged-in users, by /api/system/health.
    Checks: evidence store, agent store, license (a license problem does not make the
    server not ready: it has already started).
    """
    checks: dict = {}
    ok = True

    try:
        from evidence_store.store import get_store
        get_store().count("__healthcheck__")
        checks["evidence_store"] = "ok"
    except Exception as e:
        logger.warning("Readiness: evidence store check failed: %s", e)
        checks["evidence_store"] = "error"
        ok = False

    try:
        from agent_store.store import get_agent_store
        _ = get_agent_store().list_agents()
        checks["agent_store"] = "ok"
    except Exception as e:
        logger.warning("Readiness: agent store check failed: %s", e)
        checks["agent_store"] = "error"
        ok = False

    try:
        from license import validate_license
        validate_license()
        checks["license"] = "valid"
    except Exception as e:
        logger.warning("Readiness: license check failed: %s", e)
        checks["license"] = "invalid"

    from fastapi.responses import JSONResponse
    return JSONResponse({"ready": ok, "checks": checks}, status_code=200 if ok else 503)


@app.get("/api/system/health")
async def system_health(_user: User = Depends(get_current_user)):
    """
    Detailed system health for the dashboard panel.
    Requires authentication. Returns health of all subsystems + disk/version info.
    """
    import shutil
    import sys
    import platform as _platform

    checks: dict = {}

    # Evidence store
    try:
        from evidence_store.store import get_store
        checks["evidence_store"] = {"status": "ok"}
    except Exception as e:
        checks["evidence_store"] = {"status": "error", "detail": str(e)}

    # Agent store (the count covers only organizations this user can access)
    try:
        from agent_store.store import get_agent_store
        from api.auth_deps import can_access_org
        agent_count = sum(1 for a in get_agent_store().list_agents() if can_access_org(_user, a.org_id))
        checks["agent_store"] = {"status": "ok", "agents": agent_count}
    except Exception as e:
        checks["agent_store"] = {"status": "error", "detail": str(e)}

    # License
    try:
        from license import LicenseError, validate_license
        lic = validate_license()
        checks["license"] = {
            "status": "valid",
            "org": lic.org,
            "tier": lic.tier,
            "expiry": lic.expiry,
            "days_remaining": lic.days_remaining,
        }
    except Exception as e:
        checks["license"] = {"status": "error", "detail": str(e)}

    # TLS
    try:
        from tls import cert_path, tls_mode, cert_fingerprint
        mode = tls_mode()
        if mode == "false":
            checks["tls"] = {"status": "disabled"}
        elif cert_path().exists():
            fp = cert_fingerprint()
            from tls import cert_days_remaining
            days = cert_days_remaining()
            state = "active"
            if days is not None and days < 0:
                state = "expired"
            elif days is not None and days <= 30:
                state = "expiring"
            checks["tls"] = {"status": state, "fingerprint": fp, "days_remaining": days}
        else:
            checks["tls"] = {"status": "no_cert"}
    except Exception as e:
        checks["tls"] = {"status": "error", "detail": str(e)}

    # Disk space
    try:
        from runtime_paths import data_root
        usage = shutil.disk_usage(str(data_root()))
        free_pct = round(usage.free / usage.total * 100, 1)
        checks["disk"] = {
            "status": "ok" if free_pct > 10 else "low",
            "free_pct": free_pct,
            "free_gb": round(usage.free / 1e9, 2),
            "total_gb": round(usage.total / 1e9, 2),
        }
    except Exception as e:
        checks["disk"] = {"status": "error", "detail": str(e)}

    # Secrets file permissions
    try:
        from secret_manager import audit_secret_permissions
        perm = audit_secret_permissions()
        all_ok = all(v == "ok" for v in perm.values())
        checks["secrets"] = {"status": "ok" if all_ok else "permissions_issue", "files": perm}
    except Exception as e:
        checks["secrets"] = {"status": "error", "detail": str(e)}

    # AI subsystem
    try:
        from ai_config import ai_provider_info
        ai_info = ai_provider_info()
        checks["ai"] = {"status": "ok", **ai_info}
    except Exception as e:
        checks["ai"] = {"status": "error", "detail": str(e)}

    # Backups and evidence-chain checks
    try:
        import maintenance
        checks["maintenance"] = maintenance.assess()
    except Exception as e:
        checks["maintenance"] = {"status": "error", "problem": str(e)}

    # Detection: how events are being processed (administrator only; see the filter below)
    try:
        from detection.pool import get_pool
        checks["detection"] = {"status": "ok", **get_pool().stats()}
    except Exception as e:
        checks["detection"] = {"status": "error", "detail": str(e)}

    # Anchoring: are checkpoints reaching witnesses the server cannot alter?
    try:
        from anchoring.checkpoints import get_manager as _anchor_manager
        _am = _anchor_manager()
        if _am is None:
            checks["anchoring"] = {"status": "disabled", "banner": False}
        else:
            _st = _am.status()
            checks["anchoring"] = {"status": "error" if _st["banner"] else "ok", "banner": _st["banner"],
                                   "single_witness": _st["single_witness"], "witnesses": _st["witnesses"],
                                   "organizations": _st["orgs"], "problems": _st["problems"]}
    except Exception as e:
        checks["anchoring"] = {"status": "error", "banner": False, "detail": str(e)}

    # Alerts and metrics: whether anyone would be told (administrator only; see the filter below)
    try:
        import alerts
        import metrics as _metrics
        channels = [name for name, on in alerts.configured().items() if on]
        checks["alerts"] = {"status": "ok" if channels else "disabled", "channels": channels,
                            "metrics_enabled": len(_metrics.token()) >= 16}
    except Exception as e:
        checks["alerts"] = {"status": "error", "detail": str(e)}

    # Runtime info
    checks["runtime"] = {
        "status": "ok",
        "python": sys.version.split()[0],
        "platform": _platform.system(),
        "version": get_version(),
        "min_agent_version": MIN_AGENT_VERSION,
    }

    overall = all(
        v.get("status") in ("ok", "valid", "active", "disabled", "pending")
        for v in checks.values()
        if isinstance(v, dict)
    )

    if _user.role != UserRole.SUPER_ADMIN:
        # Server-level detail (error text with file paths, certificate fingerprint, secret
        # file names, AI provider, Python and platform) is for the server administrator.
        # Everyone else sees the status of each check and the figures the panel shows.
        keep = {
            "evidence_store": (), "agent_store": ("agents",), "license": ("days_remaining",),
            "tls": ("days_remaining",), "disk": ("free_pct",), "runtime": ("version", "min_agent_version"),
            "anchoring": ("banner",),
        }
        checks = {
            name: {"status": v.get("status"), **{k: v[k] for k in keep[name] if k in v}}
            for name, v in checks.items() if name in keep
        }
    return {"healthy": overall, "checks": checks}


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# License info endpoint
# ---------------------------------------------------------------------------

@app.get("/api/license")
async def get_license_info(_user: User = Depends(get_current_user)):
    """
    Returns license metadata for the dashboard badge. Requires a login (it names the
    licensed customer and the expiry). Never exposes the license key itself.
    """
    try:
        info = validate_license()
        return {
            "valid":          True,
            "org":            info.org,
            "tier":           info.tier,
            "expiry":         info.expiry,
            "issued":         info.issued,
            "days_remaining": info.days_remaining,
        }
    except LicenseError as e:
        return JSONResponse({"valid": False, "error": str(e)}, status_code=403)


# Server lifecycle: start broadcaster on startup
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    # Record which loop actually owns the WebSocket clients/broadcaster —
    # see dashboard/live_feed.py's "CROSS-THREAD FIX" note. Required for
    # run_pipeline.py's cross-thread publish() calls to reach this server.
    set_server_loop(asyncio.get_running_loop())
    asyncio.create_task(broadcaster_task())
    import maintenance
    maintenance.start()      # daily backup and evidence-chain check
    from anchoring.checkpoints import get_manager as _anchor_manager
    _am = _anchor_manager()
    if _am is not None:
        _am.start()          # checkpoints of the evidence chain, copied to witnesses outside this server
    import threading as _threading

    def _group_older_findings():      # findings stored before incidents existed are grouped once, in the background
        try:
            store = get_store()
            for tenant in store.tenants():
                n = store.backfill_incidents(tenant)
                if n:
                    logger.info("Incidents: grouped %d earlier finding(s) of %s", n, tenant)
        except Exception:
            logger.warning("grouping earlier findings failed", exc_info=True)
    _threading.Thread(target=_group_older_findings, name="incident-backfill", daemon=True).start()
    from detection.pool import get_pool
    pool = get_pool()
    pool.start()             # worker processes load the language model while the server comes up
    logger.info("Detection: %s (queue limit %d)", f"{pool.workers} worker processes" if pool.workers else "one background thread", pool.queue_limit)
    logger.info("Dashboard server started. Tenant-scoped WebSocket broadcaster running.")


@app.on_event("shutdown")
async def shutdown_event():
    from anchoring.checkpoints import get_manager as _anchor_manager, reset_manager
    _am = _anchor_manager()
    if _am is not None:
        _am.stop()           # a last checkpoint, so a clean stop leaves nothing unanchored
    reset_manager()
    from detection.pool import reset_pool
    reset_pool()


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="DPDPA Dashboard Server (Phase 7)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run("dashboard.server:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
