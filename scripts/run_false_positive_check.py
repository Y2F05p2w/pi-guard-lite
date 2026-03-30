from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.collector.fluentbit_input import raw_event_from_line
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
    reset_runtime_tables()
    processor = PipelineProcessor()

    benign_lines = [
        '{"path":"/var/log/auth.log","message":"Mar 30 10:05:01 raspberrypi sshd[2233]: Accepted password for alice from 192.168.1.10 port 53001 ssh2"}',
        '{"path":"/var/log/syslog","message":"Mar 30 10:05:02 raspberrypi sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"}',
        '{"path":"/var/log/nginx/access.log","message":"192.168.1.10 - - [30/Mar/2026:10:05:05 +0800] \\"GET /health HTTP/1.1\\" 200 12 \\"-\\" \\"curl/8.0\\""}',
    ]

    results = []
    for line in benign_lines:
        raw = raw_event_from_line(line)
        if raw is None:
            continue
        results.append(processor.process_raw_event(raw, apply_policy=True, run_probe=False))

    policies = list_policies(50)
    blocklist = list_blocklist(50)
    payload = {
        "processed": len(results),
        "events": len(list_events(50)),
        "policies": policies,
        "blocklist": blocklist,
        "false_positive_detected": any(
            item.get("decision", {}).get("decision", {}).get("action") == "block_ip"
            for item in results
        ) or len(blocklist) > 0,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
