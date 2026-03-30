from __future__ import annotations

import re
from datetime import UTC, datetime

from app.common.schemas import RawInputEvent, SecurityEvent


AUTH_FAILURE_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)")
NGINX_ACCESS_RE = re.compile(
    r'(?P<src_ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) [^"]+" (?P<status>\d{3})'
)


def parse_text_log(raw_event: RawInputEvent) -> SecurityEvent:
    source = raw_event.source
    message = str(raw_event.payload.get("message", ""))
    now = datetime.now(UTC)

    if source == "auth.log":
        match = AUTH_FAILURE_RE.search(message)
        if match:
            return SecurityEvent(
                ts=now,
                source=source,
                event_type="system.auth_failure",
                src_ip=match.group("src_ip"),
                severity=2,
                username=match.group("user"),
                signature="Failed password",
                category="authentication",
                raw_path=raw_event.raw_path,
                metadata={"message": message},
            )

    if source == "nginx.access":
        match = NGINX_ACCESS_RE.search(message)
        if match:
            return SecurityEvent(
                ts=now,
                source=source,
                event_type="system.http_access",
                src_ip=match.group("src_ip"),
                severity=1,
                url=match.group("url"),
                http_method=match.group("method"),
                http_status=int(match.group("status")),
                raw_path=raw_event.raw_path,
                metadata={"message": message},
            )

    return SecurityEvent(
        ts=now,
        source=source,
        event_type=f"system.{source.replace('.', '_')}",
        severity=1,
        raw_path=raw_event.raw_path,
        metadata={"message": message},
    )
