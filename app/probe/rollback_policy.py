from __future__ import annotations

from app.common.config import get_settings
from app.common.schemas import ProbeExecutionResult


class RollbackDecider:
    def __init__(self) -> None:
        self.settings = get_settings()

    def should_rollback(self, results: list[ProbeExecutionResult]) -> tuple[bool, str]:
        probe_cfg = self.settings.get("probe", {})
        if not probe_cfg.get("rollback_on_failed_required", True):
            return False, "rollback disabled"

        failed_required = [item for item in results if item.required and not item.success]
        threshold = int(probe_cfg.get("max_failed_required", 1))
        if len(failed_required) >= threshold:
            reason = "required probes failed: " + ", ".join(item.target for item in failed_required)
            return True, reason
        return False, "probes healthy"
