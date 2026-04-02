from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.collector.scan_listener_service import ScanListenerService
from app.common.config import get_settings, resolve_path
from app.common.db import init_db
from app.common.logger import setup_logging
from app.web.auth import is_authenticated, is_exempt_path
from app.web.routes import router as web_router


setup_logging()
init_db()

settings = get_settings()
logger = logging.getLogger(__name__)

app = FastAPI(title=settings["app"].get("name", "Pi-Guard Lite"))
static_dir = resolve_path(settings["paths"].get("static_dir", "static"))
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
app.include_router(web_router)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if is_exempt_path(path):
        return await call_next(request)
    if is_authenticated(request):
        return await call_next(request)

    accept = request.headers.get("accept", "")
    if "text/html" in accept or path == "/" or path.endswith("/view"):
        return RedirectResponse(url="/login", status_code=303)
    return JSONResponse({"detail": "unauthorized"}, status_code=401)


@app.on_event("startup")
def on_startup() -> None:
    logger.info("Pi-Guard Lite started")
    service = ScanListenerService(settings.get("scan_listener", {}))
    app.state.scan_listener_service = service
    status = service.start()
    logger.info("scan listener startup status: %s", status)


@app.on_event("shutdown")
def on_shutdown() -> None:
    service = getattr(app.state, "scan_listener_service", None)
    if service:
        service.stop()
        logger.info("scan listener stopped")
