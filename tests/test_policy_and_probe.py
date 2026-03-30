from __future__ import annotations

import unittest

from app.common.schemas import FeatureVector, PolicyDecision, ProbeExecutionResult, RiskScoreResult, SecurityEvent
from app.policy.generator import PolicyGenerator
from app.probe.rollback_policy import RollbackDecider


class PolicyAndProbeTestCase(unittest.TestCase):
    def test_policy_generator_blocks_critical_event(self) -> None:
        generator = PolicyGenerator()
        event = SecurityEvent(
            ts="2026-03-30T10:00:00+08:00",
            source="suricata",
            event_type="suricata.alert",
            src_ip="203.0.113.10",
            dst_ip="192.168.1.20",
            severity=3,
        )
        features = FeatureVector(event_type=event.event_type, src_ip=event.src_ip, asset_importance=5)
        risk = RiskScoreResult(risk_score=96, risk_level="critical")
        decision = generator.generate(event, features, risk)
        self.assertEqual(decision.action, "block_ip")
        self.assertEqual(decision.target, "203.0.113.10")
        self.assertGreater(decision.ttl_seconds, 0)

    def test_policy_generator_respects_whitelist(self) -> None:
        generator = PolicyGenerator()
        event = SecurityEvent(
            ts="2026-03-30T10:00:00+08:00",
            source="suricata",
            event_type="suricata.http",
            src_ip="127.0.0.1",
            severity=1,
        )
        features = FeatureVector(event_type=event.event_type, src_ip=event.src_ip, is_whitelisted=True)
        risk = RiskScoreResult(risk_score=90, risk_level="critical")
        decision = generator.generate(event, features, risk)
        self.assertEqual(decision.action, "alert")

    def test_rollback_decider_detects_required_probe_failure(self) -> None:
        decider = RollbackDecider()
        results = [
            ProbeExecutionResult(
                target="http://127.0.0.1:8080/health",
                probe_type="http",
                success=False,
                required=True,
                detail="connection failed",
            )
        ]
        should_rollback, reason = decider.should_rollback(results)
        self.assertTrue(should_rollback)
        self.assertIn("required probes failed", reason)


if __name__ == "__main__":
    unittest.main()
