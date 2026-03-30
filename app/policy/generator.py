from __future__ import annotations

from app.common.config import get_settings
from app.common.schemas import FeatureVector, PolicyDecision, RiskScoreResult, SecurityEvent


class PolicyGenerator:
    def __init__(self) -> None:
        self.settings = get_settings()

    def generate(
        self,
        event: SecurityEvent,
        features: FeatureVector,
        risk: RiskScoreResult,
    ) -> PolicyDecision:
        risk_cfg = self.settings.get("risk", {})
        critical_ttl = int(risk_cfg.get("block_ttl_minutes", 30)) * 60
        high_ttl = int(risk_cfg.get("high_ttl_minutes", 15)) * 60

        if not event.src_ip:
            return PolicyDecision(action="record", reason="事件缺少源 IP，仅记录。")

        if features.is_whitelisted:
            return PolicyDecision(
                action="alert",
                target=event.src_ip,
                reason="命中白名单，降级为告警，不自动封禁。",
            )

        if risk.risk_level == "critical":
            return PolicyDecision(
                action="block_ip",
                target=event.src_ip,
                ttl_seconds=critical_ttl,
                status="pending",
                reason="风险等级为 critical，执行临时封禁。",
            )

        if risk.risk_level == "high":
            return PolicyDecision(
                action="block_ip",
                target=event.src_ip,
                ttl_seconds=high_ttl,
                status="pending",
                reason="风险等级为 high，执行短时封禁。",
            )

        if risk.risk_level == "medium":
            return PolicyDecision(
                action="alert",
                target=event.src_ip,
                reason="风险等级为 medium，记录告警，暂不封禁。",
            )

        return PolicyDecision(
            action="record",
            target=event.src_ip,
            reason="风险较低，仅记录事件。",
        )
