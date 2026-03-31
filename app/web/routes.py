from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
from urllib.parse import quote

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.common.assets import get_asset, list_assets
from app.common.config import get_settings, resolve_path
from app.common.dashboard import build_dashboard_summary
from app.common.db import get_connection
from app.common.event_store import get_analysis_result, get_event, get_feature, list_events
from app.common.notifier import Notifier
from app.common.schemas import HealthResponse, ManualBlockRequest, ManualUnblockRequest, StatsResponse
from app.detector.ml_engine import MLInferenceEngine
from app.detector.model_manager import ModelManager
from app.executor.factory import get_executor
from app.policy.repository import (
    get_blocklist_entry,
    get_policy,
    list_blocklist,
    list_blocklist_by_target,
    list_policies,
    list_policies_by_target,
    list_probe_results,
    list_probe_results_by_policy,
)
from app.policy.service import PolicyService
from app.probe.checker import ProbeChecker
from app.web.auth import get_auth_config, get_cookie_name, verify_credentials


router = APIRouter()
settings = get_settings()
templates = Jinja2Templates(
    directory=str(resolve_path(settings["paths"].get("templates_dir", "templates")))
)


def _count(conn: sqlite3.Connection, table: str) -> int:
    row = conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
    return int(row["count"]) if row else 0


def _render_page(request: Request, template_name: str, active_nav: str, **context) -> HTMLResponse:
    scan_listener_service = getattr(request.app.state, "scan_listener_service", None)
    ctx = {
        "settings": settings,
        "request": request,
        "active_nav": active_nav,
        "current_user": request.cookies.get(get_cookie_name(), ""),
        "scan_listener_status": scan_listener_service.status() if scan_listener_service else {},
        "notifier_status": Notifier().status(),
    }
    ctx.update(context)
    return templates.TemplateResponse(request=request, name=template_name, context=ctx)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    auth = get_auth_config()
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "request": request,
            "settings": settings,
            "title": auth.get("login_title", "Pi-Guard Lite"),
            "message": request.query_params.get("message", ""),
        },
    )


@router.post("/login", response_model=None)
async def login_submit(request: Request) -> Response:
    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))
    if not verify_credentials(username, password):
        msg = quote("登录失败：用户名或密码错误")
        return RedirectResponse(url=f"/login?message={msg}", status_code=303)
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(get_cookie_name(), username, httponly=True, samesite="lax")
    return response


@router.get("/logout", response_model=None)
def logout() -> Response:
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(get_cookie_name())
    return response


@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    scan_listener_service = getattr(request.app.state, "scan_listener_service", None)
    dashboard = build_dashboard_summary(
        scan_listener_status=scan_listener_service.status() if scan_listener_service else {},
        notifier_status=Notifier().status(),
    )
    return _render_page(
        request,
        "index.html",
        "dashboard",
        **dashboard,
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


@router.get("/dashboard/summary")
def dashboard_summary(request: Request) -> dict:
    scan_listener_service = getattr(request.app.state, "scan_listener_service", None)
    return build_dashboard_summary(
        scan_listener_status=scan_listener_service.status() if scan_listener_service else {},
        notifier_status=Notifier().status(),
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
    parsed_result = None
    if result:
        parsed_result = dict(result)
        for key in ("findings_json", "mitre_json", "impacted_assets_json"):
            parsed_result[key] = json.loads(parsed_result[key] or "[]")
        parsed_result["graph_json"] = json.loads(parsed_result["graph_json"] or "{}")
    return _render_page(
        request,
        "analysis.html",
        "analysis",
        event_id=event_id,
        result=parsed_result,
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
    return _render_page(request, "events.html", "events", items=list_events(limit=100))


@router.get("/events/view/{event_id}", response_class=HTMLResponse)
def event_detail_view(request: Request, event_id: int) -> HTMLResponse:
    event = get_event(event_id)
    feature = get_feature(event_id)
    analysis = get_analysis_result(event_id)
    parsed_analysis = None
    if analysis:
        parsed_analysis = dict(analysis)
        for key in ("findings_json", "mitre_json", "impacted_assets_json"):
            parsed_analysis[key] = json.loads(parsed_analysis[key] or "[]")
        parsed_analysis["graph_json"] = json.loads(parsed_analysis["graph_json"] or "{}")
    return _render_page(
        request,
        "event_detail.html",
        "events",
        event=event,
        feature=feature,
        analysis=parsed_analysis,
    )


@router.get("/policies/view", response_class=HTMLResponse)
def policies_view(request: Request) -> HTMLResponse:
    return _render_page(request, "policies.html", "policies", items=list_policies(limit=100))


@router.get("/policies/view/{policy_id}", response_class=HTMLResponse)
def policy_detail_view(request: Request, policy_id: int) -> HTMLResponse:
    policy = get_policy(policy_id)
    probes = list_probe_results_by_policy(policy_id, limit=50)
    related_blocklist = list_blocklist_by_target(policy["target"], limit=20) if policy else []
    related_event = get_event(policy["event_id"]) if policy and policy.get("event_id") else None
    return _render_page(
        request,
        "policy_detail.html",
        "policies",
        policy=policy,
        probes=probes,
        related_blocklist=related_blocklist,
        related_event=related_event,
    )


@router.get("/blocklist/view", response_class=HTMLResponse)
def blocklist_view(request: Request) -> HTMLResponse:
    return _render_page(request, "blocklist.html", "blocklist", items=list_blocklist(limit=100))


@router.get("/blocklist/view/{block_id}", response_class=HTMLResponse)
def blocklist_detail_view(request: Request, block_id: int) -> HTMLResponse:
    entry = get_blocklist_entry(block_id)
    related_policies = list_policies_by_target(entry["target_ip"], limit=20) if entry else []
    return _render_page(
        request,
        "blocklist_detail.html",
        "blocklist",
        entry=entry,
        related_policies=related_policies,
    )


@router.get("/probes/view", response_class=HTMLResponse)
def probes_view(request: Request) -> HTMLResponse:
    items = list_probe_results(limit=100)
    summary = {
        "total": len(items),
        "success": len([item for item in items if item["result"] == "success"]),
        "failed": len([item for item in items if item["result"] != "success"]),
    }
    return _render_page(request, "probes.html", "probes", items=items, summary=summary)


@router.get("/assets/view", response_class=HTMLResponse)
def assets_view(request: Request) -> HTMLResponse:
    return _render_page(request, "assets.html", "assets", items=list_assets())


@router.get("/assets/view/{ip}", response_class=HTMLResponse)
def asset_detail_view(request: Request, ip: str) -> HTMLResponse:
    asset = get_asset(ip)
    related_events = [item for item in list_events(limit=200) if item.get("dst_ip") == ip or item.get("src_ip") == ip][:50]
    related_policies = list_policies_by_target(ip, limit=50)
    related_blocklist = list_blocklist_by_target(ip, limit=50)
    return _render_page(
        request,
        "asset_detail.html",
        "assets",
        asset=asset,
        related_events=related_events,
        related_policies=related_policies,
        related_blocklist=related_blocklist,
    )


@router.get("/manual/view", response_class=HTMLResponse)
def manual_view(request: Request) -> HTMLResponse:
    message = request.query_params.get("message", "")
    level = request.query_params.get("level", "info")
    executor_result = get_executor().check_connection().model_dump()
    return _render_page(
        request,
        "manual.html",
        "manual",
        message=message,
        level=level,
        executor_result=executor_result,
        recent_policies=list_policies(limit=10),
        recent_blocklist=list_blocklist(limit=10),
    )


@router.get("/executor/check")
def executor_check() -> dict:
    result = get_executor().check_connection()
    return result.model_dump()


@router.get("/probe/run")
def run_probe() -> list[dict]:
    checker = ProbeChecker()
    return [item.model_dump() for item in checker.run_default_targets()]


@router.get("/scan-listener/status")
def scan_listener_status(request: Request) -> dict:
    service = getattr(request.app.state, "scan_listener_service", None)
    if service is None:
        return {"enabled": False, "running": False, "detail": "service not initialized"}
    return service.status()


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
    return _render_page(
        request,
        "notifications.html",
        "notifications",
        message=request.query_params.get("message", ""),
        level=request.query_params.get("level", "info"),
        status=notifier.status(),
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
    return _render_page(
        request,
        "models.html",
        "models",
        message=request.query_params.get("message", ""),
        level=request.query_params.get("level", "info"),
        status=manager.get_status(),
        grouped_versions=manager.grouped_versions(),
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
