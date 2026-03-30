from __future__ import annotations

from app.common.schemas import FeatureVector, MLInferenceResult, RiskScoreResult, RuleMatch, SecurityEvent


class RiskScorer:
    def __init__(self, alert_threshold: float = 40, block_threshold: float = 85) -> None:
        self.alert_threshold = alert_threshold
        self.block_threshold = block_threshold

    def score(
        self,
        event: SecurityEvent,
        features: FeatureVector,
        matches: list[RuleMatch],
        ml_result: MLInferenceResult | None = None,
    ) -> RiskScoreResult:
        base_score = min(max(event.severity, 0) * 10, 30)
        rule_score = sum(match.score for match in matches)
        asset_bonus = min(features.asset_importance * 5, 25)
        behavior_bonus = 5 if features.off_hours else 0
        blacklist_bonus = 20 if features.hits_blacklist else 0
        whitelist_penalty = 40 if features.is_whitelisted else 0
        baseline_bonus = min(features.baseline_score, 25)
        ml_bonus = 0.0
        if ml_result and ml_result.model_loaded:
            ml_bonus = min((ml_result.anomaly_score * 0.15) + (ml_result.classifier_score * 0.25), 25.0)

        anomaly_score = round(
            min(
                100.0,
                features.request_count_1m * 0.8
                + features.unique_dst_ports_5m * 2
                + features.login_failures_5m * 3
                + features.http_error_ratio_5m * 20,
            ),
            2,
        )
        risk_score = base_score + rule_score + asset_bonus + behavior_bonus + blacklist_bonus + baseline_bonus + ml_bonus
        risk_score += anomaly_score * 0.15
        risk_score -= whitelist_penalty
        risk_score = round(max(0.0, min(100.0, risk_score)), 2)

        if risk_score >= self.block_threshold:
            risk_level = "critical"
        elif risk_score >= 70:
            risk_level = "high"
        elif risk_score >= self.alert_threshold:
            risk_level = "medium"
        else:
            risk_level = "low"

        return RiskScoreResult(
            anomaly_score=anomaly_score,
            ml_score=round(ml_bonus, 2),
            risk_score=risk_score,
            risk_level=risk_level,
            reasons=[match.reason for match in matches] + ([ml_result.reason] if ml_result and ml_result.reason else []),
        )
