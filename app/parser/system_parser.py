from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from app.common.schemas import RawInputEvent, SecurityEvent


AUTH_FAILURE_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)")
AUTH_SUCCESS_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)")
NGINX_ACCESS_RE = re.compile(
    r'(?P<src_ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) [^"]+" (?P<status>\d{3})'
)
NGINX_ERROR_RE = re.compile(r'client: (?P<src_ip>\d+\.\d+\.\d+\.\d+).*(?P<message>upstream|connect\(\) failed|permission denied)', re.IGNORECASE)
SYSLOG_SSH_FAIL_RE = re.compile(r"sshd\[\d+\]: Failed password for (invalid user )?(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)")
SYSLOG_SSH_ACCEPT_RE = re.compile(r"sshd\[\d+\]: Accepted password for (?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)")
SYSLOG_SUDO_RE = re.compile(r"sudo: +(?P<user>\S+) : .*COMMAND=(?P<command>.+)$")


def parse_text_log(raw_event: RawInputEvent) -> SecurityEvent:
    source = raw_event.source
    message = str(raw_event.payload.get("message", ""))
    now = datetime.now(UTC)

    if source in {"scan.demo", "scan.listener"}:
        try:
            payload = json.loads(message)
            return SecurityEvent(
                ts=now,
                source=source,
                event_type="system.scan_probe",
                src_ip=str(payload.get("src_ip", "")) or None,
                dst_ip=str(payload.get("dst_ip", "")) or None,
                dst_port=int(payload.get("dst_port")) if payload.get("dst_port") is not None else None,
                protocol=str(payload.get("protocol", "tcp")),
                severity=2,
                signature="local scan demo",
                category="network",
                raw_path=raw_event.raw_path,
                metadata=payload,
            )
        except Exception:
            return SecurityEvent(
                ts=now,
                source=source,
                event_type="system.scan_probe",
                severity=1,
                signature="local scan demo",
                category="network",
                raw_path=raw_event.raw_path,
                metadata={"message": message},
            )

    if source in {"edr.process", "sample.report", "edr.sysmon", "sample.sandbox"}:
        try:
            payload = json.loads(message)
        except Exception:
            payload = {"message": message}

        if source in {"edr.process", "edr.sysmon"}:
            process_name = payload.get("process_name") or payload.get("Image") or payload.get("image")
            command_line = payload.get("command_line") or payload.get("CommandLine") or payload.get("commandline")
            parent_process = payload.get("parent_process_name") or payload.get("ParentImage") or payload.get("parent_image")
            return SecurityEvent(
                ts=now,
                source=source,
                event_type="edr.process",
                src_ip=str(payload.get("host_ip") or payload.get("HostIp") or payload.get("host_ip_address") or "" ) or None,
                dst_ip=str(payload.get("dst_ip", "")) or None,
                severity=int(payload.get("severity", 2)),
                username=payload.get("user") or payload.get("User"),
                signature=str(process_name or "process_start"),
                category="process",
                raw_path=raw_event.raw_path,
                metadata={
                    **payload,
                    "process_name": process_name,
                    "command_line": command_line,
                    "parent_process_name": parent_process,
                },
            )

        return SecurityEvent(
            ts=now,
            source=source,
            event_type="sample.report",
            severity=int(payload.get("severity", 2)),
            signature=str(payload.get("file_name") or payload.get("fileName") or "sample"),
            category="sample",
            raw_path=raw_event.raw_path,
            metadata={
                **payload,
                "file_name": payload.get("file_name") or payload.get("fileName"),
                "entropy": payload.get("entropy", payload.get("Entropy")),
                "yara_hits": payload.get("yara_hits", payload.get("yaraHits", [])),
                "sandbox_verdict": payload.get("sandbox_verdict", payload.get("verdict")),
            },
        )

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
        match = AUTH_SUCCESS_RE.search(message)
        if match:
            return SecurityEvent(
                ts=now,
                source=source,
                event_type="system.auth_success",
                src_ip=match.group("src_ip"),
                severity=0,
                username=match.group("user"),
                signature="Accepted password",
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

    if source == "nginx.error":
        match = NGINX_ERROR_RE.search(message)
        if match:
            return SecurityEvent(
                ts=now,
                source=source,
                event_type="system.nginx_error",
                src_ip=match.group("src_ip"),
                severity=2,
                signature="nginx error",
                category="http",
                raw_path=raw_event.raw_path,
                metadata={"message": message},
            )

    if source == "syslog":
        match = SYSLOG_SSH_FAIL_RE.search(message)
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
        match = SYSLOG_SSH_ACCEPT_RE.search(message)
        if match:
            return SecurityEvent(
                ts=now,
                source=source,
                event_type="system.auth_success",
                src_ip=match.group("src_ip"),
                severity=0,
                username=match.group("user"),
                signature="Accepted password",
                category="authentication",
                raw_path=raw_event.raw_path,
                metadata={"message": message},
            )
        match = SYSLOG_SUDO_RE.search(message)
        if match:
            return SecurityEvent(
                ts=now,
                source=source,
                event_type="system.privilege_use",
                severity=1,
                username=match.group("user"),
                signature="sudo command",
                category="privilege",
                raw_path=raw_event.raw_path,
                metadata={"message": message, "command": match.group("command")},
            )

    return SecurityEvent(
        ts=now,
        source=source,
        event_type=f"system.{source.replace('.', '_')}",
        severity=1,
        raw_path=raw_event.raw_path,
        metadata={"message": message},
    )
