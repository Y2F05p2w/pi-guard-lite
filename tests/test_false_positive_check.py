from __future__ import annotations

import unittest

from app.collector.fluentbit_input import raw_event_from_line
from app.common.db import get_connection, init_db
from app.policy.pipeline import PipelineProcessor
from app.policy.repository import list_blocklist
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class FalsePositiveCheckTestCase(unittest.TestCase):
    def setUp(self) -> None:
        setup_isolated_db(self.__class__.__name__)
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

    def tearDown(self) -> None:
        cleanup_isolated_db()

    def test_benign_inputs_do_not_create_blocklist(self) -> None:
        processor = PipelineProcessor()
        benign_lines = [
            '{"path":"/var/log/auth.log","message":"Mar 30 10:05:01 raspberrypi sshd[2233]: Accepted password for alice from 192.168.1.10 port 53001 ssh2"}',
            '{"path":"/var/log/nginx/access.log","message":"192.168.1.10 - - [30/Mar/2026:10:05:05 +0800] \\"GET /health HTTP/1.1\\" 200 12 \\"-\\" \\"curl/8.0\\""}',
        ]
        for line in benign_lines:
            raw = raw_event_from_line(line)
            assert raw is not None
            processor.process_raw_event(raw, apply_policy=True, run_probe=False)
        self.assertEqual(len(list_blocklist(20)), 0)


if __name__ == "__main__":
    unittest.main()
