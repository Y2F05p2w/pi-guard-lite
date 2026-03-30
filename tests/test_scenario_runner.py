from __future__ import annotations

import unittest

from app.collector.fluentbit_input import raw_event_from_line
from app.collector.suricata_reader import SuricataFileReader
from app.common.db import get_connection, init_db
from app.policy.pipeline import PipelineProcessor
from app.policy.repository import list_blocklist, list_policies


class ScenarioRunnerTestCase(unittest.TestCase):
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

    def test_suricata_critical_event_creates_policy(self) -> None:
        processor = PipelineProcessor()
        sample = SuricataFileReader("tests/samples/suricata_eve.jsonl")
        first_raw = next(iter(sample.read_existing()))
        result = processor.process_raw_event(first_raw, apply_policy=True, run_probe=False)
        self.assertEqual(result["event"]["event_type"], "suricata.alert")
        self.assertIn(result["risk"]["risk_level"], {"critical", "high"})
        self.assertEqual(result["decision"]["decision"]["action"], "block_ip")
        self.assertGreaterEqual(len(list_policies(10)), 1)
        self.assertGreaterEqual(len(list_blocklist(10)), 1)

    def test_fluentbit_line_processes_to_auth_failure(self) -> None:
        processor = PipelineProcessor()
        line = '{"path":"/var/log/auth.log","message":"Mar 30 10:00:01 raspberrypi sshd[1234]: Failed password for invalid user admin from 203.0.113.20 port 52888 ssh2"}'
        raw_event = raw_event_from_line(line)
        assert raw_event is not None
        result = processor.process_raw_event(raw_event, apply_policy=False, run_probe=False)
        self.assertEqual(result["event"]["event_type"], "system.auth_failure")


if __name__ == "__main__":
    unittest.main()
