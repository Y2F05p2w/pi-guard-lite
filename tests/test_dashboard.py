from __future__ import annotations

import unittest

from app.common.dashboard import build_dashboard_summary
from app.common.db import get_connection, init_db
from app.common.schemas import SecurityEvent
from app.common.event_store import insert_event
from app.policy.repository import create_policy
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class DashboardSummaryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        setup_isolated_db(self.__class__.__name__)
        init_db()
        with get_connection() as conn:
            for table in ("event", "policy", "blocklist", "probe_result", "audit_log", "feature", "analysis_result"):
                conn.execute(f"DELETE FROM {table}")
            conn.commit()

    def tearDown(self) -> None:
        cleanup_isolated_db()

    def test_build_dashboard_summary(self) -> None:
        event = SecurityEvent(
            ts="2026-03-31T10:00:00+08:00",
            source="suricata",
            event_type="suricata.alert",
            src_ip="203.0.113.10",
            dst_ip="192.168.1.20",
            severity=2,
        )
        event_id = insert_event(event)
        with get_connection() as conn:
            conn.execute("UPDATE event SET risk_level = 'critical', risk_score = 98 WHERE id = ?", (event_id,))
            conn.commit()
        create_policy(event_id=event_id, action="block_ip", target="203.0.113.10", ttl_seconds=60, status="simulated")
        result = build_dashboard_summary(
            scan_listener_status={"running": True},
            notifier_status={"enabled": False},
        )
        self.assertEqual(result["stats"]["events"], 1)
        self.assertEqual(result["risk_summary"]["critical"], 1)
        self.assertEqual(result["stats"]["policies"], 1)
