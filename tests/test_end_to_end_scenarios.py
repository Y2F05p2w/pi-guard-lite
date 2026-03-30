from __future__ import annotations

import unittest
from pathlib import Path

from app.collector.fluentbit_input import raw_event_from_line
from app.collector.suricata_reader import SuricataFileReader
from app.collector.system_reader import TextLogFileReader
from app.common.db import get_connection, init_db
from app.policy.pipeline import PipelineProcessor
from app.policy.repository import list_blocklist, list_policies


class EndToEndScenariosTestCase(unittest.TestCase):
    def setUp(self) -> None:
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

    def test_suricata_critical_alert_generates_block_policy(self) -> None:
        sample = Path(__file__).parent / "samples" / "suricata_eve.jsonl"
        raw_event = next(iter(SuricataFileReader(sample).read_existing()))
        result = PipelineProcessor().process_raw_event(raw_event, apply_policy=True, run_probe=False)
        self.assertEqual(result["decision"]["decision"]["action"], "block_ip")
        self.assertEqual(len(list_policies(10)), 1)
        self.assertEqual(len(list_blocklist(10)), 1)

    def test_fluentbit_and_authlog_pipeline(self) -> None:
        auth_raw = next(iter(TextLogFileReader(Path(__file__).parent / "samples" / "auth.log", source="auth.log").read_existing()))
        fluent_raw = raw_event_from_line(
            '{"path":"/var/log/syslog","message":"Mar 30 10:00:11 raspberrypi sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"}'
        )
        processor = PipelineProcessor()
        auth_result = processor.process_raw_event(auth_raw, apply_policy=False, run_probe=False)
        fluent_result = processor.process_raw_event(fluent_raw, apply_policy=False, run_probe=False)
        self.assertEqual(auth_result["event"]["event_type"], "system.auth_failure")
        self.assertEqual(fluent_result["event"]["event_type"], "system.privilege_use")


if __name__ == "__main__":
    unittest.main()
