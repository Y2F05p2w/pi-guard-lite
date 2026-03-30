from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.collector.suricata_reader import SuricataFileReader
from app.collector.system_reader import TextLogFileReader
from app.common.db import init_db
from app.common.logger import setup_logging
from app.policy.pipeline import PipelineProcessor


def iter_source(source: str, file_path: str, mode: str):
    if source == "suricata":
        reader = SuricataFileReader(file_path)
    else:
        reader = TextLogFileReader(file_path, source=source)
    return reader.read_existing() if mode == "existing" else reader.tail()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Pi-Guard Lite pipeline service")
    parser.add_argument("--source", required=True, help="suricata | auth.log | nginx.access | syslog")
    parser.add_argument("--file", required=True, help="Input file path")
    parser.add_argument("--mode", choices=["existing", "tail"], default="tail")
    parser.add_argument("--no-policy", action="store_true")
    parser.add_argument("--no-probe", action="store_true")
    args = parser.parse_args()

    setup_logging()
    init_db()
    processor = PipelineProcessor()
    logger = logging.getLogger(__name__)
    logger.info("pipeline service starting source=%s file=%s mode=%s", args.source, args.file, args.mode)

    for raw_event in iter_source(args.source, args.file, args.mode):
        result = processor.process_raw_event(
            raw_event,
            apply_policy=not args.no_policy,
            run_probe=not args.no_probe,
        )
        logger.info(
            "pipeline processed event_id=%s type=%s risk=%s",
            result["event_id"],
            result["event"]["event_type"],
            result["risk"]["risk_score"],
        )


if __name__ == "__main__":
    main()
