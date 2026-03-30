from __future__ import annotations

from typing import Any

from app.common.config import get_settings


EXEMPT_PATHS = {
    "/health",
    "/login",
    "/logout",
}

EXEMPT_PREFIXES = (
    "/static",
)


def get_auth_config() -> dict:
    settings = get_settings()
    return settings.get("auth", {})


def get_cookie_name() -> str:
    return str(get_auth_config().get("cookie_name", "pi_guard_auth"))


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
