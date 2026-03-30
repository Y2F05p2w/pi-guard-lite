from __future__ import annotations

import unittest

from app.collector.fluentbit_input import raw_event_from_line
from app.common.db import get_connection, init_db
from app.common.event_store import list_events
from app.policy.pipeline import PipelineProcessor


class PipelineIntegrationTestCase(unittest.TestCase):
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

    def test_process_fluentbit_auth_line(self) -> None:
        line = '{"message":"Mar 30 10:00:01 raspberrypi sshd[1234]: Failed password for invalid user admin from 203.0.113.20 port 52888 ssh2","path":"/var/log/auth.log"}'
        raw_event = raw_event_from_line(line)
        assert raw_event is not None
        processor = PipelineProcessor()
        result = processor.process_raw_event(raw_event, apply_policy=False, run_probe=False)
        self.assertEqual(result["event"]["event_type"], "system.auth_failure")
        self.assertGreater(result["risk"]["risk_score"], 0)
        self.assertEqual(len(list_events(10)), 1)


if __name__ == "__main__":
    unittest.main()
