from __future__ import annotations

import argparse
import logging
import sys
import threading
from pathlib import Path

import yaml

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


def worker(entry: dict) -> None:
    logger = logging.getLogger(f"input-supervisor:{entry['name']}")
    processor = PipelineProcessor()
    logger.info("starting source=%s file=%s mode=%s", entry["source"], entry["file"], entry["mode"])
    for raw_event in iter_source(entry["source"], entry["file"], entry["mode"]):
        result = processor.process_raw_event(
            raw_event,
            apply_policy=bool(entry.get("apply_policy", True)),
            run_probe=bool(entry.get("run_probe", True)),
        )
        logger.info("processed event_id=%s type=%s risk=%s", result["event_id"], result["event"]["event_type"], result["risk"]["risk_score"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Pi-Guard Lite multi-input supervisor")
    parser.add_argument("--config", default="config/inputs.yaml", help="YAML config path")
    args = parser.parse_args()

    setup_logging()
    init_db()
    cfg_path = Path(args.config)
    if not cfg_path.is_absolute():
        cfg_path = PROJECT_ROOT / cfg_path
    with cfg_path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    inputs = cfg.get("inputs", [])
    if not inputs:
        raise SystemExit("no inputs configured")

    threads = []
    for entry in inputs:
        thread = threading.Thread(target=worker, args=(entry,), daemon=True)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
