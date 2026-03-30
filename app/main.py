from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.common.config import get_settings
from app.common.db import init_db
from app.common.logger import setup_logging
from app.web.auth import is_authenticated, is_exempt_path
from app.web.routes import router as web_router


setup_logging()
init_db()

settings = get_settings()
logger = logging.getLogger(__name__)

app = FastAPI(title=settings["app"].get("name", "Pi-Guard Lite"))
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
