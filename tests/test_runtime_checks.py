from __future__ import annotations

import unittest

from app.common.runtime_checks import collect_runtime_report, parse_vcgencmd_temp


class RuntimeChecksTestCase(unittest.TestCase):
    def test_parse_vcgencmd_temp(self) -> None:
        self.assertEqual(parse_vcgencmd_temp("temp=54.8'C\n"), 54.8)
        self.assertIsNone(parse_vcgencmd_temp("invalid"))

    def test_collect_runtime_report_shape(self) -> None:
        report = collect_runtime_report()
        self.assertIn("host", report)
        self.assertIn("resources", report)
        self.assertIn("systemd", report)
        self.assertIn("binaries", report)


if __name__ == "__main__":
    unittest.main()
