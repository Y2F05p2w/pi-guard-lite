from __future__ import annotations

import unittest

from app.common.db import get_connection, init_db
from app.policy.repository import list_blocklist, list_policies
from app.policy.service import PolicyService
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class PolicyServiceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        setup_isolated_db(self.__class__.__name__)
        init_db()
        with get_connection() as conn:
            for table in ("policy", "blocklist", "probe_result", "audit_log"):
                conn.execute(f"DELETE FROM {table}")
            conn.commit()

    def tearDown(self) -> None:
        cleanup_isolated_db()

    def test_manual_block_and_unblock_in_dry_run(self) -> None:
        service = PolicyService()
        policy_id, block_result = service.manual_block_ip("203.0.113.50", 60, "unit test block")
        self.assertIsNotNone(policy_id)
        self.assertIsNotNone(block_result)
        self.assertTrue(block_result.success)

        policies = list_policies(10)
        blocklist = list_blocklist(10)
        self.assertEqual(len(policies), 1)
        self.assertEqual(len(blocklist), 1)
        self.assertEqual(blocklist[0]["target_ip"], "203.0.113.50")

        unblock_result = service.manual_unblock_ip("203.0.113.50", "unit test release")
        self.assertTrue(unblock_result.success)


if __name__ == "__main__":
    unittest.main()
