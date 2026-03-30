from __future__ import annotations

import unittest
from unittest.mock import patch

from app.common.notifier import Notifier


class NotifierTestCase(unittest.TestCase):
    def test_disabled_notifier_skips(self) -> None:
        with patch("app.common.notifier.get_settings", return_value={"notifier": {"enabled": False}}):
            result = Notifier().send("title", "message")
            self.assertTrue(result.success)
            self.assertFalse(result.sent)

    def test_webhook_notifier_posts(self) -> None:
        settings = {
            "notifier": {
                "enabled": True,
                "channel": "webhook",
                "webhook_url": "https://example.invalid/hook",
                "timeout_seconds": 1,
            }
        }
        with patch("app.common.notifier.get_settings", return_value=settings):
            with patch("app.common.notifier.requests.post") as mock_post:
                mock_post.return_value.status_code = 200
                mock_post.return_value.raise_for_status.return_value = None
                result = Notifier().send("title", "message", {"a": 1})
                self.assertTrue(result.success)
                self.assertTrue(result.sent)
                mock_post.assert_called_once()


if __name__ == "__main__":
    unittest.main()
