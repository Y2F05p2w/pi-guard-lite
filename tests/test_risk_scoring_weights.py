from __future__ import annotations

import unittest

from app.common.schemas import FeatureVector, SecurityEvent
from app.scorer.risk_scoring import RiskScorer


class RiskScoringWeightsTestCase(unittest.TestCase):
    def test_custom_weights_raise_score(self) -> None:
        event = SecurityEvent(
            ts="2026-03-30T10:00:00+08:00",
            source="suricata",
            event_type="suricata.http",
            src_ip="203.0.113.10",
            dst_ip="192.168.1.30",
            severity=1,
        )
        features = FeatureVector(
            event_type=event.event_type,
            src_ip=event.src_ip,
            asset_importance=3,
            request_count_1m=20,
            baseline_score=10,
        )
        default_score = RiskScorer().score(event, features, []).risk_score
        weighted_score = RiskScorer(
            weights={
                "severity_per_level": 20,
                "asset_importance": 10,
                "anomaly_multiplier": 0.3,
            }
        ).score(event, features, []).risk_score
        self.assertGreater(weighted_score, default_score)


if __name__ == "__main__":
    unittest.main()
