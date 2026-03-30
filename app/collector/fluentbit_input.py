from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.common.schemas import RawInputEvent


def infer_source(record: dict[str, Any]) -> str:
    explicit = record.get("source") or record.get("tag") or record.get("input")
    if explicit:
        return str(explicit)

    raw_path = record.get("raw_path") or record.get("file") or record.get("path")
    if raw_path:
        name = Path(str(raw_path)).name.lower()
        if name == "auth.log":
            return "auth.log"
        if name == "syslog":
            return "syslog"
        if name == "access.log":
            return "nginx.access"
        if name == "error.log":
            return "nginx.error"

    return "syslog"


def raw_event_from_fluentbit_record(record: dict[str, Any]) -> RawInputEvent:
    if "source" in record and "payload" in record:
        return RawInputEvent(
            source=str(record["source"]),
            payload=dict(record["payload"]),
            raw_path=record.get("raw_path"),
        )

    source = infer_source(record)

    if "message" in record:
        payload = {"message": record["message"]}
    elif "log" in record:
        payload = {"message": record["log"]}
    else:
        payload = dict(record)

    raw_path = record.get("raw_path") or record.get("file") or record.get("path")
    return RawInputEvent(source=source, payload=payload, raw_path=raw_path)


def raw_event_from_line(line: str) -> RawInputEvent | None:
    line = line.strip()
    if not line:
        return None
    record = json.loads(line)
    if not isinstance(record, dict):
        raise ValueError("fluent bit line must be a json object")
    return raw_event_from_fluentbit_record(record)
