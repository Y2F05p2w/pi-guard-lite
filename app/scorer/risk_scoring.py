from __future__ import annotations

from app.common.config import get_settings
from app.common.schemas import FeatureVector, MLInferenceResult, RiskScoreResult, RuleMatch, SecurityEvent


class RiskScorer:
    def __init__(
        self,
        alert_threshold: float = 40,
        block_threshold: float = 85,
        weights: dict | None = None,
    ) -> None:
        self.alert_threshold = alert_threshold
        self.block_threshold = block_threshold
        self.weights = weights or {}

    @classmethod
    def from_settings(cls) -> "RiskScorer":
        settings = get_settings()
        risk_cfg = settings.get("risk", {})
        return cls(
            alert_threshold=float(risk_cfg.get("alert_threshold", 40)),
            block_threshold=float(risk_cfg.get("block_threshold", 85)),
            weights=risk_cfg.get("weights", {}),
        )

    def score(
        self,
        event: SecurityEvent,
        features: FeatureVector,
        matches: list[RuleMatch],
        ml_result: MLInferenceResult | None = None,
    ) -> RiskScoreResult:
        severity_per_level = float(self.weights.get("severity_per_level", 10))
        severity_cap = float(self.weights.get("severity_cap", 30))
        asset_weight = float(self.weights.get("asset_importance", 5))
        asset_cap = float(self.weights.get("asset_cap", 25))
        off_hours_bonus = float(self.weights.get("off_hours_bonus", 5))
        blacklist_bonus_weight = float(self.weights.get("blacklist_bonus", 20))
        whitelist_penalty = float(self.weights.get("whitelist_penalty", 40))
        baseline_cap = float(self.weights.get("baseline_cap", 25))
        anomaly_multiplier = float(self.weights.get("anomaly_multiplier", 0.15))
        ml_anomaly_multiplier = float(self.weights.get("ml_anomaly_multiplier", 0.15))
        ml_classifier_multiplier = float(self.weights.get("ml_classifier_multiplier", 0.25))

        base_score = min(max(event.severity, 0) * severity_per_level, severity_cap)
        rule_score = sum(match.score for match in matches)
        asset_bonus = min(features.asset_importance * asset_weight, asset_cap)
        behavior_bonus = off_hours_bonus if features.off_hours else 0
        blacklist_bonus = blacklist_bonus_weight if features.hits_blacklist else 0
        whitelist_penalty = whitelist_penalty if features.is_whitelisted else 0
        baseline_bonus = min(features.baseline_score, baseline_cap)
        ml_bonus = 0.0
        if ml_result and ml_result.model_loaded:
            ml_bonus = min(
                (ml_result.anomaly_score * ml_anomaly_multiplier)
                + (ml_result.classifier_score * ml_classifier_multiplier),
                25.0,
            )

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
        risk_score += anomaly_score * anomaly_multiplier
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
