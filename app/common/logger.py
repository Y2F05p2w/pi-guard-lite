from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.common.config import get_settings, resolve_path


def setup_logging() -> None:
    settings = get_settings()
    logs_dir = resolve_path(settings["paths"].get("logs_dir", "logs"))
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = Path(logs_dir) / "app.log"

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)

    file_handler = RotatingFileHandler(
        log_file, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)
