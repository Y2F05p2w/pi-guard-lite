from __future__ import annotations

import yaml

from app.common.config import PROJECT_ROOT
from app.executor.openwrt_executor import OpenWrtSSHExecutor


def load_executor_config() -> dict:
    path = PROJECT_ROOT / "config" / "executor.yaml"
    if not path.exists():
        return {"executor": {"type": "ssh", "dry_run": True}}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {"executor": {"type": "ssh", "dry_run": True}}


def get_executor() -> OpenWrtSSHExecutor:
    config = load_executor_config().get("executor", {})
    return OpenWrtSSHExecutor(config)
