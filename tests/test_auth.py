from __future__ import annotations

import unittest
from unittest.mock import patch

from app.web.auth import get_cookie_name, is_exempt_path, verify_credentials


class AuthHelpersTestCase(unittest.TestCase):
    def test_verify_credentials(self) -> None:
        settings = {"auth": {"username": "admin", "password": "admin", "cookie_name": "pi_guard_auth"}}
        with patch("app.web.auth.get_settings", return_value=settings):
            self.assertTrue(verify_credentials("admin", "admin"))
            self.assertFalse(verify_credentials("admin", "wrong"))
            self.assertEqual(get_cookie_name(), "pi_guard_auth")

    def test_is_exempt_path(self) -> None:
        self.assertTrue(is_exempt_path("/health"))
        self.assertTrue(is_exempt_path("/login"))
        self.assertFalse(is_exempt_path("/events"))


if __name__ == "__main__":
    unittest.main()
