from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.common.config import get_settings, resolve_path
from app.common.db import get_connection
from app.common.event_store import list_events
from app.common.schemas import HealthResponse, ManualBlockRequest, ManualUnblockRequest, StatsResponse
from app.executor.factory import get_executor
from app.policy.repository import list_blocklist, list_policies, list_probe_results
from app.policy.service import PolicyService
from app.probe.checker import ProbeChecker


router = APIRouter()
settings = get_settings()
templates = Jinja2Templates(
    directory=str(resolve_path(settings["paths"].get("templates_dir", "templates")))
)


def _count(conn: sqlite3.Connection, table: str) -> int:
    row = conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
    return int(row["count"]) if row else 0


@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    with get_connection() as conn:
        stats = {
            "events": _count(conn, "event"),
            "policies": _count(conn, "policy"),
            "blocked": _count(conn, "blocklist"),
        }
    recent_events = list_events(limit=10)
    recent_policies = list_policies(limit=10)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "stats": stats,
            "settings": settings,
            "recent_events": recent_events,
            "recent_policies": recent_policies,
        },
    )


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", app=settings["app"].get("name", "Pi-Guard Lite"))


@router.get("/stats", response_model=StatsResponse)
def stats() -> StatsResponse:
    with get_connection() as conn:
        return StatsResponse(
            events=_count(conn, "event"),
            policies=_count(conn, "policy"),
            blocked=_count(conn, "blocklist"),
        )


@router.get("/events")
def events(limit: int = 20) -> list[dict]:
    return list_events(limit=limit)


@router.get("/policies")
def policies(limit: int = 20) -> list[dict]:
    return list_policies(limit=limit)


@router.get("/blocklist")
def blocklist(limit: int = 20) -> list[dict]:
    return list_blocklist(limit=limit)


@router.get("/events/view", response_class=HTMLResponse)
def events_view(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="events.html",
        context={"items": list_events(limit=100), "settings": settings},
    )


@router.get("/policies/view", response_class=HTMLResponse)
def policies_view(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="policies.html",
        context={"items": list_policies(limit=100), "settings": settings},
    )


@router.get("/blocklist/view", response_class=HTMLResponse)
def blocklist_view(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="blocklist.html",
        context={"items": list_blocklist(limit=100), "settings": settings},
    )


@router.get("/probes/view", response_class=HTMLResponse)
def probes_view(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="probes.html",
        context={"items": list_probe_results(limit=100), "settings": settings},
    )


@router.get("/manual/view", response_class=HTMLResponse)
def manual_view(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="manual.html",
        context={"settings": settings},
    )


@router.get("/executor/check")
def executor_check() -> dict:
    result = get_executor().check_connection()
    return result.model_dump()


@router.get("/probe/run")
def run_probe() -> list[dict]:
    checker = ProbeChecker()
    return [item.model_dump() for item in checker.run_default_targets()]


@router.post("/manual/block")
async def manual_block(request: Request, payload: ManualBlockRequest | None = None) -> dict:
    if payload is None:
        form = await request.form()
        payload = ManualBlockRequest(
            ip=str(form.get("ip", "")),
            ttl_seconds=int(form.get("ttl_seconds", 1800)),
            reason=str(form.get("reason", "manual block")),
        )
    service = PolicyService()
    policy_id, result = service.manual_block_ip(
        ip=payload.ip,
        ttl_seconds=payload.ttl_seconds,
        reason=payload.reason,
    )
    return {
        "policy_id": policy_id,
        "result": result.model_dump() if result else None,
    }


@router.post("/manual/unblock")
async def manual_unblock(request: Request, payload: ManualUnblockRequest | None = None) -> dict:
    if payload is None:
        form = await request.form()
        payload = ManualUnblockRequest(
            ip=str(form.get("ip", "")),
            reason=str(form.get("reason", "manual unblock")),
        )
    service = PolicyService()
    result = service.manual_unblock_ip(
        ip=payload.ip,
        reason=payload.reason,
    )
    return result.model_dump()
