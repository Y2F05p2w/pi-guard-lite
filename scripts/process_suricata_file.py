from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.collector.raw_store import append_raw_event
from app.collector.suricata_reader import SuricataFileReader
from app.common.config import get_settings
from app.common.db import init_db
from app.common.event_store import insert_audit_log, insert_event, insert_feature, update_event_scores
from app.common.logger import setup_logging
from app.detector.rule_engine import RuleEngine
from app.features.extractor import FeatureExtractor
from app.parser.suricata_parser import parse_suricata_event
from app.scorer.risk_scoring import RiskScorer


def process_file(file_path: str) -> int:
    settings = get_settings()
    reader = SuricataFileReader(file_path)
    extractor = FeatureExtractor()
    rule_engine = RuleEngine()
    scorer = RiskScorer(
        alert_threshold=float(settings["risk"].get("alert_threshold", 40)),
        block_threshold=float(settings["risk"].get("block_threshold", 85)),
    )
    total = 0
    for raw_event in reader.read_existing():
        stored_raw_path = append_raw_event(raw_event)
        raw_event.raw_path = stored_raw_path
        event = parse_suricata_event(raw_event)
        features = extractor.extract(event)
        matches = rule_engine.evaluate(event, features)
        risk = scorer.score(event, features, matches)

        event_id = insert_event(event)
        insert_feature(event_id, features)
        update_event_scores(event_id, risk)
        insert_audit_log(
            category="pipeline",
            action="process_suricata_event",
            detail={
                "event_id": event_id,
                "event_type": event.event_type,
                "risk_score": risk.risk_score,
                "risk_level": risk.risk_level,
            },
        )
        logging.getLogger(__name__).info(
            "processed event_id=%s event_type=%s risk=%s level=%s",
            event_id,
            event.event_type,
            risk.risk_score,
            risk.risk_level,
        )
        total += 1
    return total


def main() -> None:
    parser = argparse.ArgumentParser(description="Process Suricata eve.json file")
    parser.add_argument("file", help="Path to eve.json or sample jsonl file")
    args = parser.parse_args()

    setup_logging()
    init_db()
    total = process_file(args.file)
    logging.getLogger(__name__).info("processed %s events in total", total)


if __name__ == "__main__":
    main()
