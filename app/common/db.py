from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from app.common.config import PROJECT_ROOT, get_settings, resolve_path


def get_db_path() -> Path:
    settings = get_settings()
    db_path = resolve_path(settings["paths"].get("database", "data/pi_guard.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return db_path


@contextmanager
def get_connection():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    sql_file = PROJECT_ROOT / "scripts" / "init_db.sql"
    with sql_file.open("r", encoding="utf-8") as f:
        schema = f.read()
    with get_connection() as conn:
        conn.executescript(schema)
        _ensure_column(conn, "event", "source", "TEXT DEFAULT 'unknown'")
        _ensure_column(conn, "event", "risk_level", "TEXT DEFAULT 'low'")
        _ensure_column(conn, "event", "ml_score", "REAL DEFAULT 0")
        conn.commit()


def _ensure_column(
    conn: sqlite3.Connection,
    table_name: str,
    column_name: str,
    column_sql: str,
) -> None:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    existing_columns = {row["name"] for row in rows}
    if column_name in existing_columns:
        return
    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}")
