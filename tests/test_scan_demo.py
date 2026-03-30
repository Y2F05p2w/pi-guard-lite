from __future__ import annotations

import unittest

from app.common.db import get_connection, init_db
from app.common.schemas import RawInputEvent
from app.parser.system_parser import parse_text_log
from app.policy.pipeline import PipelineProcessor
from app.policy.repository import list_blocklist
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class ScanDemoTestCase(unittest.TestCase):
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

    def test_scan_demo_parser(self) -> None:
        raw = RawInputEvent(
            source="scan.demo",
            payload={"message": '{"src_ip":"127.0.0.2","dst_ip":"127.0.0.1","dst_port":2201,"protocol":"tcp"}'},
        )
        event = parse_text_log(raw)
        self.assertEqual(event.event_type, "system.scan_probe")
        self.assertEqual(event.src_ip, "127.0.0.2")
        self.assertEqual(event.dst_port, 2201)

    def test_scan_demo_triggers_block(self) -> None:
        processor = PipelineProcessor()
        for port in range(2201, 2213):
            raw = RawInputEvent(
                source="scan.demo",
                payload={"message": f'{{"src_ip":"127.0.0.2","dst_ip":"127.0.0.1","dst_port":{port},"protocol":"tcp"}}'},
            )
            processor.process_raw_event(raw, apply_policy=True, run_probe=False)
        self.assertGreaterEqual(len(list_blocklist(30)), 1)


if __name__ == "__main__":
    unittest.main()
