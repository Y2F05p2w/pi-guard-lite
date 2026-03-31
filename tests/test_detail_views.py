from __future__ import annotations

import unittest

from app.common.db import get_connection, init_db
from app.common.event_store import insert_event, insert_feature, upsert_analysis_result
from app.common.schemas import (
    AnalysisResult,
    AttackGraphEdge,
    AttackGraphNode,
    AttackTechnique,
    FeatureVector,
    SecurityEvent,
)
from app.policy.repository import add_blocklist_entry, create_policy, get_blocklist_entry, get_policy
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class DetailViewsDataTestCase(unittest.TestCase):
    def setUp(self) -> None:
        setup_isolated_db(self.__class__.__name__)
        init_db()
        with get_connection() as conn:
            for table in ("event", "feature", "policy", "blocklist", "analysis_result"):
                conn.execute(f"DELETE FROM {table}")
            conn.commit()

    def tearDown(self) -> None:
        cleanup_isolated_db()

    def test_event_policy_block_detail_data(self) -> None:
        event = SecurityEvent(
            ts="2026-03-31T12:00:00+08:00",
            source="suricata",
            event_type="suricata.alert",
            src_ip="203.0.113.10",
            dst_ip="192.168.1.20",
            severity=2,
        )
        event_id = insert_event(event)
        feature = FeatureVector(event_type=event.event_type, src_ip=event.src_ip, request_count_1m=10)
        insert_feature(event_id, feature)
        upsert_analysis_result(
            event_id,
            AnalysisResult(
                techniques=[AttackTechnique(technique_id="T1046", name="Network Service Scanning", tactic="Discovery")],
                graph_nodes=[AttackGraphNode(node_key="ip:203.0.113.10", node_type="ip", label="203.0.113.10")],
                graph_edges=[AttackGraphEdge(src_key="ip:203.0.113.10", dst_key="asset:192.168.1.20", relation="targets")],
                summary="demo",
            ),
        )
        policy_id = create_policy(event_id=event_id, action="block_ip", target="203.0.113.10", ttl_seconds=60, status="simulated")
        block_id = add_blocklist_entry("203.0.113.10", "demo", "2026-03-31T13:00:00+08:00", status="simulated")

        self.assertIsNotNone(get_policy(policy_id))
        self.assertIsNotNone(get_blocklist_entry(block_id))


if __name__ == "__main__":
    unittest.main()
