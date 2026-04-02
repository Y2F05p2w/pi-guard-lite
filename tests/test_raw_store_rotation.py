from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from app.collector.raw_store import append_raw_event
from app.common.schemas import RawInputEvent
from tests.test_helpers import cleanup_temp_dirs


class RawStoreRotationTestCase(unittest.TestCase):
    def tearDown(self) -> None:
        cleanup_temp_dirs(Path(__file__).parent / "_tmp_raw")

    def test_append_raw_event_rotates_by_line_count(self) -> None:
        raw_dir = Path(__file__).parent / "_tmp_raw"
        settings = {
            "paths": {"raw_data_dir": str(raw_dir)},
            "retention": {"raw_rotate_max_mb": 100, "raw_rotate_max_lines": 1},
        }
        event = RawInputEvent(source="syslog", payload={"message": "test"})
        with patch("app.collector.raw_store.get_settings", return_value=settings):
            first = append_raw_event(event)
            second = append_raw_event(event)

        self.assertTrue(first.endswith("-001.jsonl"))
        self.assertTrue(second.endswith("-002.jsonl"))


if __name__ == "__main__":
    unittest.main()
