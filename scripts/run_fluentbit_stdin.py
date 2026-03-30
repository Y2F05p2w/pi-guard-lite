from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.collector.fluentbit_input import raw_event_from_line
from app.common.db import init_db
from app.common.logger import setup_logging
from app.policy.pipeline import PipelineProcessor


def main() -> None:
    parser = argparse.ArgumentParser(description="Read Fluent Bit JSON lines from stdin and feed pipeline")
    parser.add_argument("--no-policy", action="store_true")
    parser.add_argument("--no-probe", action="store_true")
    args = parser.parse_args()

    setup_logging()
    init_db()
    logger = logging.getLogger(__name__)
    processor = PipelineProcessor()

    logger.info("fluentbit stdin pipeline started")
    for lineno, line in enumerate(sys.stdin, start=1):
        try:
            raw_event = raw_event_from_line(line)
            if raw_event is None:
                continue
            result = processor.process_raw_event(
                raw_event,
                apply_policy=not args.no_policy,
                run_probe=not args.no_probe,
            )
            logger.info(
                "stdin processed lineno=%s event_id=%s type=%s risk=%s",
                lineno,
                result["event_id"],
                result["event"]["event_type"],
                result["risk"]["risk_score"],
            )
        except Exception as exc:
            logger.exception("failed to process stdin line %s: %s", lineno, exc)
            print(json.dumps({"lineno": lineno, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)


if __name__ == "__main__":
    main()
