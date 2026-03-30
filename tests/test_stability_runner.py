from __future__ import annotations

import unittest
from pathlib import Path

from app.collector.suricata_reader import SuricataFileReader
from app.common.db import get_connection, init_db
from app.common.event_store import list_events
from app.policy.pipeline import PipelineProcessor
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class StabilityRunnerTestCase(unittest.TestCase):
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

    def test_multiple_iterations_keep_processing(self) -> None:
        processor = PipelineProcessor()
        sample = list(SuricataFileReader(Path("tests/samples/suricata_eve.jsonl")).read_existing())
        for _ in range(3):
            for raw in sample:
                processor.process_raw_event(raw, apply_policy=False, run_probe=False)
        self.assertEqual(len(list_events(100)), len(sample) * 3)


if __name__ == "__main__":
    unittest.main()
