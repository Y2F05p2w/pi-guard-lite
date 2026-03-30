from __future__ import annotations

import unittest

from app.common.db import get_connection, init_db
from app.common.schemas import FeatureVector, SecurityEvent
from app.detector.baseline import BaselineEngine
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class BaselineEngineTestCase(unittest.TestCase):
    def setUp(self) -> None:
        setup_isolated_db(self.__class__.__name__)
        init_db()
        with get_connection() as conn:
            conn.execute("DELETE FROM baseline_profile")
            conn.commit()

    def tearDown(self) -> None:
        cleanup_isolated_db()

    def test_baseline_marks_new_source_then_learns(self) -> None:
        engine = BaselineEngine()
        event = SecurityEvent(
            ts="2026-03-30T10:00:00+08:00",
            source="suricata",
            event_type="suricata.http",
            src_ip="203.0.113.60",
            dst_ip="192.168.1.30",
            dst_port=80,
            severity=1,
        )
        features = FeatureVector(event_type=event.event_type, src_ip=event.src_ip)
        first = engine.enrich(event, features)
        self.assertFalse(first.known_source)
        self.assertGreater(first.baseline_score, 0)

        second_features = FeatureVector(event_type=event.event_type, src_ip=event.src_ip)
        second = engine.enrich(event, second_features)
        self.assertTrue(second.known_source)
        self.assertTrue(second.known_event_type)
        self.assertEqual(second.baseline_score, 0.0)


if __name__ == "__main__":
    unittest.main()
