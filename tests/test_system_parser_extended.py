from __future__ import annotations

import unittest
from pathlib import Path

from app.collector.system_reader import TextLogFileReader
from app.parser.system_parser import parse_text_log


class SystemParserExtendedTestCase(unittest.TestCase):
    def test_syslog_parse(self) -> None:
        sample = Path(__file__).parent / "samples" / "syslog.log"
        reader = TextLogFileReader(sample, source="syslog")
        items = list(reader.read_existing())
        self.assertEqual(len(items), 2)
        first = parse_text_log(items[0])
        second = parse_text_log(items[1])
        self.assertEqual(first.event_type, "system.auth_failure")
        self.assertEqual(first.src_ip, "203.0.113.21")
        self.assertEqual(second.event_type, "system.privilege_use")
        self.assertEqual(second.username, "alice")

    def test_nginx_error_parse(self) -> None:
        sample = Path(__file__).parent / "samples" / "nginx.error.log"
        reader = TextLogFileReader(sample, source="nginx.error")
        items = list(reader.read_existing())
        self.assertEqual(len(items), 1)
        event = parse_text_log(items[0])
        self.assertEqual(event.event_type, "system.nginx_error")
        self.assertEqual(event.src_ip, "203.0.113.22")


if __name__ == "__main__":
    unittest.main()
