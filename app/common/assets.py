from __future__ import annotations

from functools import lru_cache

import yaml

from app.common.config import PROJECT_ROOT


ASSETS_FILE = PROJECT_ROOT / "config" / "assets.yaml"


@lru_cache(maxsize=1)
def load_assets() -> dict[str, dict]:
    if not ASSETS_FILE.exists():
        return {}
    with ASSETS_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    assets = {}
    for item in data.get("assets", []):
        ip = item.get("ip")
        if ip:
            assets[ip] = item
    return assets


def get_asset_importance(ip: str | None) -> int:
    if not ip:
        return 1
    asset = load_assets().get(ip)
    if not asset:
        return 1
    return int(asset.get("importance", 1))
