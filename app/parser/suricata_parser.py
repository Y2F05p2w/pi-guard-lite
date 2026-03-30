from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.common.schemas import RawInputEvent, SecurityEvent


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    value = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return datetime.now(UTC)


def _get_ip(raw: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = raw.get(key)
        if value:
            return str(value)
    return None


def parse_suricata_event(raw_event: RawInputEvent) -> SecurityEvent:
    payload = raw_event.payload
    raw_type = str(payload.get("event_type", "unknown"))
    base_metadata = {"flow_id": payload.get("flow_id"), "in_iface": payload.get("in_iface")}
    base = dict(
        ts=_parse_ts(payload.get("timestamp")),
        source="suricata",
        event_type=f"suricata.{raw_type}",
        src_ip=_get_ip(payload, "src_ip"),
        dst_ip=_get_ip(payload, "dest_ip", "dst_ip"),
        src_port=payload.get("src_port"),
        dst_port=payload.get("dest_port", payload.get("dst_port")),
        protocol=payload.get("proto"),
        service=payload.get("app_proto"),
        sensor=payload.get("host"),
        raw_path=raw_event.raw_path,
    )

    if raw_type == "alert":
        alert = payload.get("alert", {})
        return SecurityEvent(
            **base,
            severity=int(alert.get("severity", 0)),
            signature=alert.get("signature"),
            category=alert.get("category"),
            action=payload.get("verdict") or alert.get("action"),
            metadata=base_metadata,
        )

    if raw_type == "dns":
        dns = payload.get("dns", {})
        return SecurityEvent(
            **base,
            severity=1,
            domain=dns.get("rrname"),
            action=dns.get("type"),
            metadata={
                **base_metadata,
                "rcode": dns.get("rcode"),
                "rrtype": dns.get("rrtype"),
            },
        )

    if raw_type == "http":
        http = payload.get("http", {})
        url = http.get("url")
        hostname = http.get("hostname")
        if hostname and url and not str(url).startswith("http"):
            url = f"http://{hostname}{url}"
        return SecurityEvent(
            **base,
            severity=1,
            url=url,
            http_method=http.get("http_method"),
            http_status=http.get("status"),
            metadata={
                **base_metadata,
                "hostname": hostname,
                "user_agent": http.get("http_user_agent"),
            },
        )

    if raw_type == "tls":
        tls = payload.get("tls", {})
        return SecurityEvent(
            **base,
            severity=1,
            tls_sni=tls.get("sni"),
            metadata={
                **base_metadata,
                "issuerdn": tls.get("issuerdn"),
                "subject": tls.get("subject"),
            },
        )

    if raw_type == "anomaly":
        anomaly = payload.get("anomaly", {})
        return SecurityEvent(
            **base,
            severity=2,
            signature=anomaly.get("type"),
            category=anomaly.get("event"),
            metadata={
                **base_metadata,
                "layer": anomaly.get("layer"),
            },
        )

    return SecurityEvent(**base, severity=0, metadata=base_metadata)
