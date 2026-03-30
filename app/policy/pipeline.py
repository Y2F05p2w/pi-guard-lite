from __future__ import annotations

from typing import Iterable

from app.collector.raw_store import append_raw_event
from app.common.config import get_settings
from app.common.event_store import (
    insert_audit_log,
    insert_event,
    insert_feature,
    update_event_scores,
    upsert_analysis_result,
)
from app.common.schemas import RawInputEvent, SecurityEvent
from app.detector.advanced_analysis import AdvancedAnalyzer
from app.detector.baseline import BaselineEngine
from app.detector.ml_engine import MLInferenceEngine
from app.detector.rule_engine import RuleEngine
from app.features.extractor import FeatureExtractor
from app.parser.suricata_parser import parse_suricata_event
from app.parser.system_parser import parse_text_log
from app.policy.generator import PolicyGenerator
from app.policy.service import PolicyService
from app.probe.rollback_runner import RollbackRunner
from app.scorer.risk_scoring import RiskScorer


class PipelineProcessor:
    def __init__(self) -> None:
        self.extractor = FeatureExtractor()
        self.baseline = BaselineEngine()
        self.advanced_analyzer = AdvancedAnalyzer()
        self.ml_engine = MLInferenceEngine()
        self.rule_engine = RuleEngine()
        self.policy_generator = PolicyGenerator()
        self.policy_service = PolicyService()
        self.rollback_runner = RollbackRunner()
        self.scorer = RiskScorer.from_settings()

    def process_raw_event(
        self,
        raw_event: RawInputEvent,
        apply_policy: bool = True,
        run_probe: bool = True,
    ) -> dict:
        stored_raw_path = append_raw_event(raw_event)
        raw_event.raw_path = stored_raw_path

        event = self.parse_raw_event(raw_event)
        features = self.extractor.extract(event)
        features = self.baseline.enrich(event, features)
        matches = self.rule_engine.evaluate(event, features)
        ml_result = self.ml_engine.infer(features)
        risk = self.scorer.score(event, features, matches, ml_result=ml_result)
        analysis = self.advanced_analyzer.analyze(event, features, matches, ml_result)

        event_id = insert_event(event)
        insert_feature(event_id, features)
        update_event_scores(event_id, risk)
        upsert_analysis_result(event_id, analysis)

        decision_payload = None
        execution_payload = None
        rollback_payload = None

        if apply_policy:
            decision = self.policy_generator.generate(event, features, risk)
            policy_id, exec_result = self.policy_service.apply_decision(event_id, decision)
            decision_payload = {
                "policy_id": policy_id,
                "decision": decision.model_dump(),
            }
            execution_payload = exec_result.model_dump() if exec_result else None
            if run_probe and policy_id and decision.action == "block_ip":
                rollback_payload = self.rollback_runner.run_for_policy(policy_id)

        payload = {
            "event_id": event_id,
            "event": event.model_dump(mode="json"),
            "features": features.model_dump(),
            "risk": risk.model_dump(),
            "matches": [match.model_dump() for match in matches],
            "ml": ml_result.model_dump(),
            "analysis": analysis.model_dump(),
            "decision": decision_payload,
            "execution": execution_payload,
            "rollback": rollback_payload,
        }
        insert_audit_log("pipeline", "process_raw_event", payload)
        return payload

    def process_many(
        self,
        events: Iterable[RawInputEvent],
        apply_policy: bool = True,
        run_probe: bool = True,
    ) -> list[dict]:
        return [
            self.process_raw_event(raw_event, apply_policy=apply_policy, run_probe=run_probe)
            for raw_event in events
        ]

    def parse_raw_event(self, raw_event: RawInputEvent) -> SecurityEvent:
        if raw_event.source == "suricata":
            return parse_suricata_event(raw_event)
        return parse_text_log(raw_event)
