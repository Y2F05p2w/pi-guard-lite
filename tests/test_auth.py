from __future__ import annotations

import unittest
from unittest.mock import patch

from app.web.auth import (
    can_attempt_login,
    clear_auth_runtime_state,
    get_cookie_name,
    get_login_status,
    is_exempt_path,
    register_failed_login,
    register_successful_login,
    verify_credentials,
)


class AuthHelpersTestCase(unittest.TestCase):
    def tearDown(self) -> None:
        clear_auth_runtime_state()

    def test_verify_credentials(self) -> None:
        settings = {
            "auth": {
                "username": "admin",
                "password": "admin",
                "cookie_name": "pi_guard_auth",
                "max_failed_attempts": 5,
                "lockout_seconds": 300,
            }
        }
        with patch("app.web.auth.get_settings", return_value=settings):
            self.assertTrue(verify_credentials("admin", "admin"))
            self.assertFalse(verify_credentials("admin", "wrong"))
            self.assertEqual(get_cookie_name(), "pi_guard_auth")

    def test_is_exempt_path(self) -> None:
        self.assertTrue(is_exempt_path("/health"))
        self.assertTrue(is_exempt_path("/login"))
        self.assertFalse(is_exempt_path("/events"))

    def test_lockout_after_failed_attempts(self) -> None:
        settings = {"auth": {"max_failed_attempts": 3, "lockout_seconds": 60}}
        with patch("app.web.auth.get_settings", return_value=settings), patch("app.web.auth.time.time", return_value=1000):
            self.assertTrue(can_attempt_login("127.0.0.1"))
            register_failed_login("127.0.0.1")
            register_failed_login("127.0.0.1")
            status = register_failed_login("127.0.0.1")
            self.assertTrue(status["locked"])
            self.assertFalse(can_attempt_login("127.0.0.1"))

    def test_success_clears_failed_attempts(self) -> None:
        settings = {"auth": {"max_failed_attempts": 3, "lockout_seconds": 60}}
        with patch("app.web.auth.get_settings", return_value=settings), patch("app.web.auth.time.time", return_value=1000):
            register_failed_login("127.0.0.1")
            self.assertEqual(get_login_status("127.0.0.1")["failed_attempts"], 1)
            register_successful_login("127.0.0.1")
            self.assertEqual(get_login_status("127.0.0.1")["failed_attempts"], 0)


if __name__ == "__main__":
    unittest.main()
