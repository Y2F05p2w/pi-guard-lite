from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.common.config import get_settings, resolve_path
from app.common.db import get_connection
from app.common.event_store import list_events
from app.common.schemas import HealthResponse, StatsResponse


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
    return templates.TemplateResponse(
        request=request, name="index.html", context={"stats": stats, "settings": settings}
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
