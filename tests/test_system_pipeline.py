from __future__ import annotations

import unittest
from pathlib import Path

from app.collector.system_reader import TextLogFileReader
from app.parser.system_parser import parse_text_log


class SystemPipelineTestCase(unittest.TestCase):
    def test_auth_log_parse(self) -> None:
        sample = Path(__file__).parent / "samples" / "auth.log"
        reader = TextLogFileReader(sample, source="auth.log")
        items = list(reader.read_existing())
        self.assertEqual(len(items), 1)
        event = parse_text_log(items[0])
        self.assertEqual(event.event_type, "system.auth_failure")
        self.assertEqual(event.src_ip, "203.0.113.20")
        self.assertEqual(event.username, "admin")


if __name__ == "__main__":
    unittest.main()
