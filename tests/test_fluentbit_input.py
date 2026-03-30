from __future__ import annotations

import unittest

from app.collector.fluentbit_input import raw_event_from_fluentbit_record, raw_event_from_line


class FluentBitInputTestCase(unittest.TestCase):
    def test_parse_message_line(self) -> None:
        line = '{"source":"syslog","message":"sshd[1]: Failed password for root from 203.0.113.9","file":"/var/log/syslog"}'
        event = raw_event_from_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.source, "syslog")
        self.assertEqual(event.payload["message"], "sshd[1]: Failed password for root from 203.0.113.9")
        self.assertEqual(event.raw_path, "/var/log/syslog")

    def test_parse_payload_record(self) -> None:
        record = {
            "source": "auth.log",
            "payload": {"message": "Failed password for admin from 203.0.113.10"},
            "raw_path": "/var/log/auth.log",
        }
        event = raw_event_from_fluentbit_record(record)
        self.assertEqual(event.source, "auth.log")
        self.assertEqual(event.raw_path, "/var/log/auth.log")
        self.assertIn("message", event.payload)

    def test_infer_source_from_path(self) -> None:
        line = '{"message":"connect() failed while connecting to upstream","path":"/var/log/nginx/error.log"}'
        event = raw_event_from_line(line)
        assert event is not None
        self.assertEqual(event.source, "nginx.error")


if __name__ == "__main__":
    unittest.main()
