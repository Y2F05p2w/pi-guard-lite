from __future__ import annotations

import unittest

from app.common.db import get_db_path, init_db
from app.policy.repository import list_blocklist, list_policies
from app.policy.service import PolicyService


class PolicyServiceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        db_path = get_db_path()
        if db_path.exists():
            db_path.unlink()
        init_db()

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
