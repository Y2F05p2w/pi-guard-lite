from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.collector.suricata_reader import SuricataFileReader
from app.common.db import get_connection, init_db
from app.common.event_store import list_events
from app.policy.pipeline import PipelineProcessor
from app.policy.repository import list_blocklist, list_policies


def reset_runtime_tables() -> None:
    init_db()
    with get_connection() as conn:
        for table in (
            "event",
            "feature",
            "policy",
            "blocklist",
            "probe_result",
            "audit_log",
            "baseline_profile",
        ):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run repeated sample processing for stability checks")
    parser.add_argument("--iterations", type=int, default=10)
    args = parser.parse_args()

    reset_runtime_tables()
    processor = PipelineProcessor()
    reader = SuricataFileReader(PROJECT_ROOT / "tests" / "samples" / "suricata_eve.jsonl")
    sample_events = list(reader.read_existing())

    for _ in range(args.iterations):
        for raw in sample_events:
            processor.process_raw_event(raw, apply_policy=True, run_probe=False)

    payload = {
        "iterations": args.iterations,
        "sample_events_per_iteration": len(sample_events),
        "total_events": len(list_events(5000)),
        "total_policies": len(list_policies(5000)),
        "total_blocklist": len(list_blocklist(5000)),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
