from __future__ import annotations

import logging

from fastapi import FastAPI

from app.common.config import get_settings
from app.common.db import init_db
from app.common.logger import setup_logging
from app.web.routes import router as web_router


setup_logging()
init_db()

settings = get_settings()
logger = logging.getLogger(__name__)

app = FastAPI(title=settings["app"].get("name", "Pi-Guard Lite"))
app.include_router(web_router)


@app.on_event("startup")
def on_startup() -> None:
    logger.info("Pi-Guard Lite started")
