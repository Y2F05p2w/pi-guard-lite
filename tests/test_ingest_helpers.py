from __future__ import annotations

import unittest

from app.common.db import get_connection, init_db
from app.common.ingest import process_ingest_batch, process_ingest_event
from app.common.schemas import IngestBatchItem
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class IngestHelpersTestCase(unittest.TestCase):
    def setUp(self) -> None:
        setup_isolated_db(self.__class__.__name__)
        init_db()

    def tearDown(self) -> None:
        cleanup_isolated_db()

    def test_process_ingest_event(self) -> None:
        result = process_ingest_event(
            source="auth.log",
            payload={"message": "Failed password for invalid user root from 203.0.113.55 port 55000 ssh2"},
            apply_policy=False,
            run_probe=False,
        )
        self.assertGreater(result["event_id"], 0)
        self.assertEqual(result["event"]["event_type"], "system.auth_failure")

    def test_process_ingest_batch(self) -> None:
        payload = process_ingest_batch(
            events=[
                IngestBatchItem(source="auth.log", payload={"message": "Failed password for invalid user root from 203.0.113.55 port 55000 ssh2"}),
                IngestBatchItem(source="syslog", payload={"message": "sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/id"}),
            ],
            apply_policy=False,
            run_probe=False,
        )
        self.assertEqual(payload["processed"], 2)
        with get_connection() as conn:
            count = conn.execute("SELECT COUNT(*) AS count FROM event").fetchone()["count"]
        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main()
