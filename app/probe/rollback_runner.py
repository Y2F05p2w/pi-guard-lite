from __future__ import annotations

from app.common.event_store import insert_audit_log
from app.policy.repository import insert_probe_result
from app.policy.service import PolicyService
from app.probe.checker import ProbeChecker
from app.probe.rollback_policy import RollbackDecider


class RollbackRunner:
    def __init__(self) -> None:
        self.policy_service = PolicyService()
        self.checker = ProbeChecker()
        self.decider = RollbackDecider()

    def run_for_policy(self, policy_id: int) -> dict:
        results = self.checker.run_default_targets()
        for item in results:
            insert_probe_result(
                policy_id=policy_id,
                probe_target=item.target,
                result="success" if item.success else "failed",
                latency_ms=item.latency_ms,
            )

        should_rollback, reason = self.decider.should_rollback(results)
        rollback_result = None
        if should_rollback:
            rollback_result = self.policy_service.rollback_policy(policy_id, reason)

        payload = {
            "policy_id": policy_id,
            "probe_results": [item.model_dump() for item in results],
            "should_rollback": should_rollback,
            "reason": reason,
            "rollback_result": rollback_result.model_dump() if rollback_result else None,
        }
        insert_audit_log("probe", "run_for_policy", payload)
        return payload
