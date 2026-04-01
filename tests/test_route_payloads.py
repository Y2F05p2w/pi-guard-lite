from __future__ import annotations

import unittest

from app.common.db import get_connection, init_db
from app.common.event_store import insert_event
from app.common.schemas import SecurityEvent
from app.policy.repository import create_policy
from app.web import routes
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class RoutePayloadHelpersTestCase(unittest.TestCase):
    def setUp(self) -> None:
        setup_isolated_db(self.__class__.__name__)
        init_db()
        with get_connection() as conn:
            for table in ("event", "policy", "blocklist", "probe_result", "audit_log", "feature", "analysis_result"):
                conn.execute(f"DELETE FROM {table}")
            conn.commit()

    def tearDown(self) -> None:
        cleanup_isolated_db()

    def test_build_events_payload_supports_search_and_pagination(self) -> None:
        insert_event(
            SecurityEvent(
                ts="2026-04-01T10:00:00+08:00",
                source="suricata",
                event_type="suricata.alert",
                src_ip="203.0.113.10",
                dst_ip="192.168.1.10",
                severity=2,
            )
        )
        insert_event(
            SecurityEvent(
                ts="2026-04-01T10:01:00+08:00",
                source="syslog",
                event_type="auth.failure",
                src_ip="10.0.0.8",
                dst_ip="192.168.1.11",
                severity=1,
            )
        )
        payload = routes._build_events_payload(
            page=1,
            page_size=1,
            sort_by="id",
            sort_order="asc",
            query="suricata",
        )
        self.assertEqual(payload["pagination"]["total"], 1)
        self.assertEqual(payload["items"][0]["event_type"], "suricata.alert")

    def test_build_policies_payload_supports_sorting(self) -> None:
        create_policy(event_id=None, action="alert", target="10.0.0.8", ttl_seconds=60, status="pending")
        create_policy(event_id=None, action="block_ip", target="203.0.113.10", ttl_seconds=300, status="applied")
        payload = routes._build_policies_payload(
            page=1,
            page_size=10,
            sort_by="action",
            sort_order="asc",
            query="",
        )
        self.assertEqual(payload["items"][0]["action"], "alert")


if __name__ == "__main__":
    unittest.main()
