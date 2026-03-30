from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
from urllib.parse import quote

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.common.assets import list_assets
from app.common.config import get_settings, resolve_path
from app.common.db import get_connection
from app.common.event_store import get_analysis_result, list_events
from app.common.notifier import Notifier
from app.common.schemas import HealthResponse, ManualBlockRequest, ManualUnblockRequest, StatsResponse
from app.detector.ml_engine import MLInferenceEngine
from app.detector.model_manager import ModelManager
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


@router.get("/analysis/event/{event_id}")
def analysis_event(event_id: int) -> dict:
    result = get_analysis_result(event_id)
    return result or {"event_id": event_id, "status": "not_found"}


@router.get("/analysis/view/{event_id}", response_class=HTMLResponse)
def analysis_view(request: Request, event_id: int) -> HTMLResponse:
    result = get_analysis_result(event_id)
    return templates.TemplateResponse(
        request=request,
        name="analysis.html",
        context={
            "settings": settings,
            "event_id": event_id,
            "result": result,
        },
    )


@router.get("/policies")
def policies(limit: int = 20) -> list[dict]:
    return list_policies(limit=limit)


@router.get("/blocklist")
def blocklist(limit: int = 20) -> list[dict]:
    return list_blocklist(limit=limit)


@router.get("/assets")
def assets() -> list[dict]:
    return list_assets()


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
    items = list_probe_results(limit=100)
    summary = {
        "total": len(items),
        "success": len([item for item in items if item["result"] == "success"]),
        "failed": len([item for item in items if item["result"] != "success"]),
    }
    return templates.TemplateResponse(
        request=request,
        name="probes.html",
        context={"items": items, "summary": summary, "settings": settings},
    )


@router.get("/assets/view", response_class=HTMLResponse)
def assets_view(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="assets.html",
        context={"items": list_assets(), "settings": settings},
    )


@router.get("/manual/view", response_class=HTMLResponse)
def manual_view(request: Request) -> HTMLResponse:
    message = request.query_params.get("message", "")
    level = request.query_params.get("level", "info")
    executor_result = get_executor().check_connection().model_dump()
    return templates.TemplateResponse(
        request=request,
        name="manual.html",
        context={
            "settings": settings,
            "message": message,
            "level": level,
            "executor_result": executor_result,
            "recent_policies": list_policies(limit=10),
            "recent_blocklist": list_blocklist(limit=10),
        },
    )


@router.get("/executor/check")
def executor_check() -> dict:
    result = get_executor().check_connection()
    return result.model_dump()


@router.get("/probe/run")
def run_probe() -> list[dict]:
    checker = ProbeChecker()
    return [item.model_dump() for item in checker.run_default_targets()]


@router.get("/ml/status")
def ml_status() -> dict:
    engine = MLInferenceEngine()
    return {
        "enabled": engine.enabled,
        "anomaly_model_loaded": engine.anomaly_model is not None,
        "classifier_model_loaded": engine.classifier_model is not None,
    }


@router.get("/notifications/status")
def notifications_status() -> dict:
    return Notifier().status()


@router.get("/notifications/view", response_class=HTMLResponse)
def notifications_view(request: Request) -> HTMLResponse:
    notifier = Notifier()
    return templates.TemplateResponse(
        request=request,
        name="notifications.html",
        context={
            "settings": settings,
            "message": request.query_params.get("message", ""),
            "level": request.query_params.get("level", "info"),
            "status": notifier.status(),
        },
    )


@router.post("/notifications/test", response_model=None)
async def notifications_test(request: Request) -> RedirectResponse | dict:
    notifier = Notifier()
    result = notifier.send(
        title="Pi-Guard test notification",
        message="manual notification test",
        payload={"source": "manual_test"},
        force=True,
    )
    if request.headers.get("content-type", ""):
        msg = quote(f"通知测试结果: {result.detail}")
        level = "success" if result.success else "info"
        return RedirectResponse(url=f"/notifications/view?message={msg}&level={level}", status_code=303)
    return result.model_dump()


@router.get("/models/versions")
def model_versions() -> list[dict]:
    return ModelManager().list_versions()


@router.get("/models/view", response_class=HTMLResponse)
def models_view(request: Request) -> HTMLResponse:
    manager = ModelManager()
    return templates.TemplateResponse(
        request=request,
        name="models.html",
        context={
            "settings": settings,
            "message": request.query_params.get("message", ""),
            "level": request.query_params.get("level", "info"),
            "status": manager.get_status(),
            "grouped_versions": manager.grouped_versions(),
        },
    )


@router.post("/models/import", response_model=None)
async def models_import(
    request: Request,
    model_name: str = Form(...),
    version: str = Form(""),
    activate: str = Form("true"),
    model_file: UploadFile = File(...),
) -> RedirectResponse | dict:
    manager = ModelManager()
    suffix = Path(model_file.filename or "model.pkl").suffix or ".pkl"
    temp_path = None
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await model_file.read())
        temp_path = tmp.name
    try:
        result = manager.import_model(
            model_name=model_name,
            source_path=temp_path,
            version=version or None,
            activate=str(activate).lower() != "false",
        )
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)
    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        msg = quote(f"模型导入完成: {result['model_name']}:{result['version']}")
        return RedirectResponse(url=f"/models/view?message={msg}&level=success", status_code=303)
    return result


@router.post("/models/activate", response_model=None)
async def models_activate(request: Request) -> RedirectResponse | dict:
    form = await request.form()
    model_name = str(form.get("model_name", ""))
    version = str(form.get("version", ""))
    result = ModelManager().activate_model(model_name, version)
    msg = quote(f"模型已激活: {model_name}:{version}")
    if request.headers.get("content-type", ""):
        return RedirectResponse(url=f"/models/view?message={msg}&level=success", status_code=303)
    return result


@router.post("/manual/block")
async def manual_block(request: Request, payload: ManualBlockRequest | None = None) -> dict:
    content_type = request.headers.get("content-type", "")
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
    if "application/x-www-form-urlencoded" in content_type:
        msg = quote(f"封禁完成: {payload.ip}")
        return RedirectResponse(url=f"/manual/view?message={msg}&level=success", status_code=303)
    return {
        "policy_id": policy_id,
        "result": result.model_dump() if result else None,
    }


@router.post("/manual/unblock")
async def manual_unblock(request: Request, payload: ManualUnblockRequest | None = None) -> dict:
    content_type = request.headers.get("content-type", "")
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
    if "application/x-www-form-urlencoded" in content_type:
        msg = quote(f"解封完成: {payload.ip}")
        return RedirectResponse(url=f"/manual/view?message={msg}&level=success", status_code=303)
    return result.model_dump()
