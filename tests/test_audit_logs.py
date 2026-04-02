from __future__ import annotations

import unittest

from app.common.db import init_db
from app.common.event_store import insert_audit_log, list_audit_logs
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class AuditLogsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        setup_isolated_db(self.__class__.__name__)
        init_db()

    def tearDown(self) -> None:
        cleanup_isolated_db()

    def test_list_audit_logs(self) -> None:
        insert_audit_log("auth", "login_success", {"client": "127.0.0.1"})
        rows = list_audit_logs(limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["category"], "auth")


if __name__ == "__main__":
    unittest.main()
