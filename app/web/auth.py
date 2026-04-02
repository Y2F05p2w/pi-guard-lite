from __future__ import annotations

import time
from typing import Any

from app.common.config import get_settings


EXEMPT_PATHS = {
    "/health",
    "/login",
    "/logout",
}

EXEMPT_PREFIXES = (
    "/static",
    "/ingest",
)

_FAILED_LOGINS: dict[str, dict[str, float | int]] = {}


def get_auth_config() -> dict:
    settings = get_settings()
    return settings.get("auth", {})


def get_cookie_name() -> str:
    return str(get_auth_config().get("cookie_name", "pi_guard_auth"))


def get_session_max_age() -> int:
    return int(get_auth_config().get("session_max_age_seconds", 28800))


def get_max_failed_attempts() -> int:
    return int(get_auth_config().get("max_failed_attempts", 5))


def get_lockout_seconds() -> int:
    return int(get_auth_config().get("lockout_seconds", 300))


def verify_credentials(username: str, password: str) -> bool:
    auth = get_auth_config()
    return username == str(auth.get("username", "admin")) and password == str(auth.get("password", "admin"))


def is_authenticated(request: Any) -> bool:
    cookie_name = get_cookie_name()
    auth = get_auth_config()
    return request.cookies.get(cookie_name) == str(auth.get("username", "admin"))


def is_exempt_path(path: str) -> bool:
    if path in EXEMPT_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in EXEMPT_PREFIXES)


def get_client_key(request: Any) -> str:
    forwarded = request.headers.get("x-forwarded-for", "") if hasattr(request, "headers") else ""
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = getattr(request, "client", None)
    if client and getattr(client, "host", ""):
        return str(client.host)
    return "unknown"


def get_login_status(client_key: str) -> dict[str, int | bool]:
    _cleanup_login_state()
    state = _FAILED_LOGINS.get(client_key)
    now = time.time()
    if not state:
        return {"locked": False, "remaining_seconds": 0, "failed_attempts": 0}
    locked_until = float(state.get("locked_until", 0))
    remaining = max(0, int(locked_until - now))
    return {
        "locked": remaining > 0,
        "remaining_seconds": remaining,
        "failed_attempts": int(state.get("failed_attempts", 0)),
    }


def can_attempt_login(client_key: str) -> bool:
    return not bool(get_login_status(client_key)["locked"])


def register_failed_login(client_key: str) -> dict[str, int | bool]:
    now = time.time()
    state = _FAILED_LOGINS.get(client_key, {"failed_attempts": 0, "locked_until": 0.0})
    failed_attempts = int(state.get("failed_attempts", 0)) + 1
    locked_until = float(state.get("locked_until", 0))
    if failed_attempts >= get_max_failed_attempts():
        locked_until = now + get_lockout_seconds()
        failed_attempts = 0
    _FAILED_LOGINS[client_key] = {
        "failed_attempts": failed_attempts,
        "locked_until": locked_until,
    }
    return get_login_status(client_key)


def register_successful_login(client_key: str) -> None:
    _FAILED_LOGINS.pop(client_key, None)


def clear_auth_runtime_state() -> None:
    _FAILED_LOGINS.clear()


def _cleanup_login_state() -> None:
    now = time.time()
    expired = [key for key, value in _FAILED_LOGINS.items() if float(value.get("locked_until", 0)) and float(value.get("locked_until", 0)) <= now]
    for key in expired:
        _FAILED_LOGINS.pop(key, None)
