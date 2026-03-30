from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app.common.config import get_settings, resolve_path


def cleanup_runtime_data(now: datetime | None = None) -> dict[str, Any]:
    settings = get_settings()
    retention = settings.get("retention", {})
    if not retention.get("cleanup_enabled", True):
        return {"enabled": False, "removed": [], "checked": []}

    now = now or datetime.now(UTC)
    removed: list[dict[str, Any]] = []
    checked: list[dict[str, Any]] = []

    raw_dir = resolve_path(settings["paths"].get("raw_data_dir", "data/raw"))
    logs_dir = resolve_path(settings["paths"].get("logs_dir", "logs"))
    backups_dir = resolve_path(settings["paths"].get("backups_dir", "backups"))

    removed += _cleanup_dir(raw_dir, int(retention.get("raw_days", 7)), now, checked)
    removed += _cleanup_dir(logs_dir, int(retention.get("log_days", 7)), now, checked)
    removed += _cleanup_dir(backups_dir, int(retention.get("backup_days", 30)), now, checked)

    return {
        "enabled": True,
        "checked": checked,
        "removed": removed,
        "removed_count": len(removed),
    }


def _cleanup_dir(
    directory: Path,
    keep_days: int,
    now: datetime,
    checked: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    if not directory.exists():
        checked.append({"path": str(directory), "exists": False, "keep_days": keep_days})
        return results

    checked.append({"path": str(directory), "exists": True, "keep_days": keep_days})
    cutoff = now - timedelta(days=keep_days)
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        if path.name == ".gitkeep":
            continue
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        if mtime < cutoff:
            path.unlink(missing_ok=True)
            results.append({"path": str(path), "mtime": mtime.isoformat()})
    return results
