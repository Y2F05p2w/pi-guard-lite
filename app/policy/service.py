from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.common.event_store import insert_audit_log
from app.common.schemas import ExecutionResult, PolicyDecision
from app.executor.factory import get_executor
from app.policy.repository import (
    add_blocklist_entry,
    create_policy,
    get_expired_blocks,
    get_policy,
    release_blocklist_by_ip,
    update_blocklist_status,
    update_policy_status,
)


class PolicyService:
    def __init__(self) -> None:
        self.executor = get_executor()

    def apply_decision(
        self,
        event_id: int | None,
        decision: PolicyDecision,
    ) -> tuple[int | None, ExecutionResult | None]:
        if decision.action in {"record", "alert"}:
            policy_id = create_policy(
                event_id=event_id,
                action=decision.action,
                target=decision.target or "n/a",
                ttl_seconds=decision.ttl_seconds,
                status="logged",
            )
            insert_audit_log("policy", "log_only", {"policy_id": policy_id, "reason": decision.reason})
            return policy_id, None

        if decision.action == "block_ip" and decision.target:
            policy_id = create_policy(
                event_id=event_id,
                action=decision.action,
                target=decision.target,
                ttl_seconds=decision.ttl_seconds,
                status="pending",
            )
            result = self.executor.block_ip(decision.target, decision.ttl_seconds)
            policy_status = "simulated" if result.simulated and result.success else ("applied" if result.success else "failed")
            update_policy_status(policy_id, policy_status)
            expire_at = (datetime.now(UTC) + timedelta(seconds=decision.ttl_seconds)).isoformat() if decision.ttl_seconds else None
            if result.success:
                add_blocklist_entry(
                    target_ip=decision.target,
                    source_reason=decision.reason,
                    expire_at=expire_at,
                    status="simulated" if result.simulated else "active",
                )
            insert_audit_log(
                "policy",
                "apply_decision",
                {
                    "policy_id": policy_id,
                    "action": decision.action,
                    "target": decision.target,
                    "result": result.model_dump(),
                },
            )
            return policy_id, result

        policy_id = create_policy(
            event_id=event_id,
            action=decision.action,
            target=decision.target or "n/a",
            ttl_seconds=decision.ttl_seconds,
            status="unsupported",
        )
        insert_audit_log("policy", "unsupported_decision", {"policy_id": policy_id, "action": decision.action})
        return policy_id, None

    def release_expired(self) -> list[dict]:
        expired = get_expired_blocks()
        results: list[dict] = []
        for block in expired:
            ip = block["target_ip"]
            exec_result = self.executor.unblock_ip(ip)
            if exec_result.success:
                update_blocklist_status(block["id"], "expired")
                release_blocklist_by_ip(ip, status="expired")
            else:
                update_blocklist_status(block["id"], "release_failed")
            insert_audit_log(
                "policy",
                "release_expired",
                {"block_id": block["id"], "target_ip": ip, "result": exec_result.model_dump()},
            )
            results.append({"block": block, "execution": exec_result.model_dump()})
        return results

    def rollback_policy(self, policy_id: int, reason: str) -> ExecutionResult | None:
        policy = get_policy(policy_id)
        if not policy or policy["action"] != "block_ip":
            return None
        target = policy["target"]
        result = self.executor.unblock_ip(target)
        if result.success:
            update_policy_status(policy_id, "rolled_back")
            release_blocklist_by_ip(target, status="released")
        insert_audit_log(
            "policy",
            "rollback_policy",
            {"policy_id": policy_id, "reason": reason, "result": result.model_dump()},
        )
        return result

    def manual_block_ip(self, ip: str, ttl_seconds: int, reason: str) -> tuple[int | None, ExecutionResult | None]:
        decision = PolicyDecision(
            action="block_ip",
            target=ip,
            ttl_seconds=ttl_seconds,
            status="pending",
            reason=reason,
        )
        return self.apply_decision(event_id=None, decision=decision)

    def manual_unblock_ip(self, ip: str, reason: str) -> ExecutionResult:
        result = self.executor.unblock_ip(ip)
        if result.success:
            release_blocklist_by_ip(ip, status="released")
            insert_audit_log(
                "policy",
                "manual_unblock",
                {"target_ip": ip, "reason": reason, "result": result.model_dump()},
            )
        else:
            insert_audit_log(
                "policy",
                "manual_unblock_failed",
                {"target_ip": ip, "reason": reason, "result": result.model_dump()},
            )
        return result
