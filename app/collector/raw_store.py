from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from app.common.config import get_settings, resolve_path
from app.common.schemas import RawInputEvent


def append_raw_event(raw_event: RawInputEvent) -> str:
    settings = get_settings()
    raw_dir = resolve_path(settings["paths"].get("raw_data_dir", "data/raw"))
    raw_dir.mkdir(parents=True, exist_ok=True)

    retention = settings.get("retention", {})
    max_file_bytes = int(retention.get("raw_rotate_max_mb", 10)) * 1024 * 1024
    max_lines = int(retention.get("raw_rotate_max_lines", 5000))

    file_path = _resolve_target_file(
        raw_dir=raw_dir,
        now=datetime.now(UTC),
        max_file_bytes=max_file_bytes,
        max_lines=max_lines,
    )
    with file_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(raw_event.model_dump(mode="json"), ensure_ascii=False) + "\n")
    return str(file_path)


def _resolve_target_file(
    *,
    raw_dir: Path,
    now: datetime,
    max_file_bytes: int,
    max_lines: int,
) -> Path:
    date_prefix = now.strftime("%Y-%m-%d")
    candidates = sorted(
        path for path in raw_dir.glob(f"{date_prefix}*.jsonl")
        if path.stem == date_prefix or path.stem.startswith(f"{date_prefix}-")
    )
    if not candidates:
        return raw_dir / f"{date_prefix}-001.jsonl"

    current = candidates[-1]
    if _needs_rotation(current, max_file_bytes=max_file_bytes, max_lines=max_lines):
        next_index = _extract_sequence(current, date_prefix) + 1
        return raw_dir / f"{date_prefix}-{next_index:03d}.jsonl"
    return current


def _needs_rotation(path: Path, *, max_file_bytes: int, max_lines: int) -> bool:
    if not path.exists():
        return False
    if max_file_bytes > 0 and path.stat().st_size >= max_file_bytes:
        return True
    if max_lines > 0:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            line_count = sum(1 for _ in f)
        if line_count >= max_lines:
            return True
    return False


def _extract_sequence(path: Path, date_prefix: str) -> int:
    stem = path.stem
    if stem == date_prefix:
        return 1
    suffix = stem.replace(f"{date_prefix}-", "", 1)
    try:
        return int(suffix)
    except ValueError:
        return 1
