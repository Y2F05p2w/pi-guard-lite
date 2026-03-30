from __future__ import annotations

import json
from datetime import UTC, datetime

from app.common.config import get_settings, resolve_path
from app.common.schemas import RawInputEvent


def append_raw_event(raw_event: RawInputEvent) -> str:
    settings = get_settings()
    raw_dir = resolve_path(settings["paths"].get("raw_data_dir", "data/raw"))
    raw_dir.mkdir(parents=True, exist_ok=True)
    file_path = raw_dir / f"{datetime.now(UTC):%Y-%m-%d}.jsonl"
    with file_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(raw_event.model_dump(mode="json"), ensure_ascii=False) + "\n")
    return str(file_path)
