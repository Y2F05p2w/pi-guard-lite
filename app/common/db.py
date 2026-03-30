from __future__ import annotations

import sqlite3
from pathlib import Path

from app.common.config import PROJECT_ROOT, get_settings, resolve_path


def get_db_path() -> Path:
    settings = get_settings()
    db_path = resolve_path(settings["paths"].get("database", "data/pi_guard.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return db_path


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    sql_file = PROJECT_ROOT / "scripts" / "init_db.sql"
    with sql_file.open("r", encoding="utf-8") as f:
        schema = f.read()
    with get_connection() as conn:
        conn.executescript(schema)
        conn.commit()
