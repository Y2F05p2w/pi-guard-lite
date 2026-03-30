from __future__ import annotations

import unittest

from app.common.preflight import run_preflight_checks


class PreflightTestCase(unittest.TestCase):
    def test_preflight_returns_summary_and_checks(self) -> None:
        result = run_preflight_checks()
        self.assertIn("summary", result)
        self.assertIn("checks", result)
        self.assertGreater(len(result["checks"]), 0)
        self.assertIn("total", result["summary"])


if __name__ == "__main__":
    unittest.main()
