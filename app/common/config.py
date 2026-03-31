from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_FILE = PROJECT_ROOT / "config" / "app.yaml"


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data


@lru_cache(maxsize=1)
def get_settings() -> dict[str, Any]:
    settings = _read_yaml(CONFIG_FILE)
    settings.setdefault("app", {})
    settings.setdefault("auth", {})
    settings.setdefault("paths", {})
    settings.setdefault("risk", {})
    settings.setdefault("probe", {})
    settings.setdefault("notifier", {})
    settings.setdefault("scan_listener", {})
    settings.setdefault("ml", {})
    return settings


def resolve_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path
