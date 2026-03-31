from __future__ import annotations

import socket
import time
import unittest

from app.common.db import get_connection, init_db
from app.policy.pipeline import PipelineProcessor
from app.policy.repository import list_blocklist
from app.collector.scan_listener import TcpScanListener, parse_port_spec
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class ScanListenerTestCase(unittest.TestCase):
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

    def test_parse_port_spec(self) -> None:
        self.assertEqual(parse_port_spec("2201-2203,2210"), [2201, 2202, 2203, 2210])
        self.assertTrue(len(parse_port_spec(None)) >= 1)

    def test_listener_emits_raw_event(self) -> None:
        events = []
        listener = TcpScanListener(
            bind_host="127.0.0.1",
            report_host="127.0.0.1",
            ports=[22991],
            on_event=lambda event: events.append(event),
        )
        listener.start()
        try:
            time.sleep(0.5)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(("127.0.0.1", 22991))
            sock.close()
            time.sleep(1)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].source, "scan.listener")
        finally:
            listener.stop()

    def test_listener_event_can_enter_pipeline(self) -> None:
        processor = PipelineProcessor()
        listener = TcpScanListener(
            bind_host="127.0.0.1",
            report_host="127.0.0.1",
            ports=[22992],
            on_event=lambda event: processor.process_raw_event(event, apply_policy=True, run_probe=False),
        )
        listener.start()
        try:
            time.sleep(0.5)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.bind(("127.0.0.2", 0))
            sock.connect(("127.0.0.1", 22992))
            sock.close()
            time.sleep(1)
            self.assertGreaterEqual(len(list_blocklist(10)), 1)
        finally:
            listener.stop()
