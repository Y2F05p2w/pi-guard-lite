from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.collector.suricata_reader import SuricataFileReader
from app.common.db import init_db
from app.common.logger import setup_logging
from app.policy.pipeline import PipelineProcessor


def process_file(file_path: str, apply_policy: bool = False, run_probe: bool = False) -> int:
    reader = SuricataFileReader(file_path)
    processor = PipelineProcessor()
    total = 0
    for raw_event in reader.read_existing():
        result = processor.process_raw_event(
            raw_event,
            apply_policy=apply_policy,
            run_probe=run_probe,
        )
        event_id = result["event_id"]
        event = result["event"]
        risk = result["risk"]
        logging.getLogger(__name__).info(
            "processed event_id=%s event_type=%s risk=%s level=%s",
            event_id,
            event["event_type"],
            risk["risk_score"],
            risk["risk_level"],
        )
        if apply_policy:
            decision = result["decision"]["decision"] if result["decision"] else {}
            policy_id = result["decision"]["policy_id"] if result["decision"] else None
            logging.getLogger(__name__).info(
                "policy event_id=%s action=%s target=%s policy_id=%s",
                event_id,
                decision.get("action"),
                decision.get("target"),
                policy_id,
            )
            if run_probe and result["rollback"] and result["rollback"]["should_rollback"]:
                    logging.getLogger(__name__).warning(
                        "rollback triggered for policy_id=%s reason=%s",
                        policy_id,
                        result["rollback"]["reason"],
                    )
        total += 1
    return total


def main() -> None:
    parser = argparse.ArgumentParser(description="Process Suricata eve.json file")
    parser.add_argument("file", help="Path to eve.json or sample jsonl file")
    parser.add_argument("--apply-policy", action="store_true", help="Generate and apply policy decisions")
    parser.add_argument("--run-probe", action="store_true", help="Run probes and rollback after block decisions")
    args = parser.parse_args()

    setup_logging()
    init_db()
    total = process_file(args.file, apply_policy=args.apply_policy, run_probe=args.run_probe)
    logging.getLogger(__name__).info("processed %s events in total", total)


if __name__ == "__main__":
    main()
