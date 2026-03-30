from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.collector.fluentbit_input import raw_event_from_line
from app.collector.suricata_reader import SuricataFileReader
from app.collector.system_reader import TextLogFileReader
from app.common.db import get_connection, init_db
from app.common.event_store import list_events
from app.policy.pipeline import PipelineProcessor
from app.policy.repository import list_blocklist, list_policies, list_probe_results


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


def run_suricata_scenario(processor: PipelineProcessor) -> dict:
    reader = SuricataFileReader(PROJECT_ROOT / "tests" / "samples" / "suricata_eve.jsonl")
    results = processor.process_many(reader.read_existing(), apply_policy=True, run_probe=False)
    return {
        "name": "suricata_pipeline",
        "processed": len(results),
        "high_or_critical": len([item for item in results if item["risk"]["risk_level"] in {"high", "critical"}]),
        "policies": len(list_policies(50)),
        "blocklist": len(list_blocklist(50)),
    }


def run_auth_scenario(processor: PipelineProcessor) -> dict:
    reader = TextLogFileReader(PROJECT_ROOT / "tests" / "samples" / "auth.log", source="auth.log")
    results = processor.process_many(reader.read_existing(), apply_policy=False, run_probe=False)
    return {
        "name": "auth_log_pipeline",
        "processed": len(results),
        "latest_event_type": results[-1]["event"]["event_type"] if results else None,
        "events_total": len(list_events(50)),
    }


def run_fluentbit_scenario(processor: PipelineProcessor) -> dict:
    sample = PROJECT_ROOT / "tests" / "samples" / "fluentbit_syslog.jsonl"
    processed = []
    for line in sample.read_text(encoding="utf-8").splitlines():
        raw_event = raw_event_from_line(line)
        if raw_event is None:
            continue
        processed.append(processor.process_raw_event(raw_event, apply_policy=False, run_probe=False))
    return {
        "name": "fluentbit_json_pipeline",
        "processed": len(processed),
        "last_event_type": processed[-1]["event"]["event_type"] if processed else None,
        "probe_rows": len(list_probe_results(50)),
    }


def main() -> None:
    reset_runtime_tables()
    processor = PipelineProcessor()
    payload = {
        "scenarios": [
            run_suricata_scenario(processor),
            run_auth_scenario(processor),
            run_fluentbit_scenario(processor),
        ],
        "totals": {
            "events": len(list_events(200)),
            "policies": len(list_policies(200)),
            "blocklist": len(list_blocklist(200)),
            "probes": len(list_probe_results(200)),
        },
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
