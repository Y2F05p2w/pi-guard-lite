from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque

from app.common.assets import get_asset_importance
from app.common.schemas import FeatureVector, SecurityEvent
from app.common.whitelist import is_domain_whitelisted, is_ip_whitelisted


class FeatureExtractor:
    def __init__(self) -> None:
        self._src_events: dict[str, Deque[tuple[datetime, str, int | None, int | None]]] = defaultdict(deque)
        self._src_http_status: dict[str, Deque[tuple[datetime, int]]] = defaultdict(deque)
        self._src_auth_failures: dict[str, Deque[datetime]] = defaultdict(deque)

    def extract(self, event: SecurityEvent) -> FeatureVector:
        src_key = event.src_ip or "unknown"
        now = event.ts

        self._track_event(src_key, event)
        if event.http_status is not None:
            self._src_http_status[src_key].append((now, int(event.http_status)))
        if self._is_auth_failure(event):
            self._src_auth_failures[src_key].append(now)

        self._cleanup(src_key, now)

        request_count_1m = sum(1 for ts, *_ in self._src_events[src_key] if ts >= now - timedelta(minutes=1))
        same_event_count_10m = sum(
            1
            for ts, event_type, *_ in self._src_events[src_key]
            if ts >= now - timedelta(minutes=10) and event_type == event.event_type
        )
        unique_dst_ports_5m = len(
            {
                dst_port
                for ts, _, _, dst_port in self._src_events[src_key]
                if ts >= now - timedelta(minutes=5) and dst_port is not None
            }
        )
        failures_5m = sum(1 for ts in self._src_auth_failures[src_key] if ts >= now - timedelta(minutes=5))

        http_recent = [status for ts, status in self._src_http_status[src_key] if ts >= now - timedelta(minutes=5)]
        http_error_ratio = 0.0
        if http_recent:
            http_error_ratio = len([code for code in http_recent if code >= 400]) / len(http_recent)

        domain = event.domain or event.tls_sni
        return FeatureVector(
            event_type=event.event_type,
            src_ip=event.src_ip,
            request_count_1m=request_count_1m,
            same_event_count_10m=same_event_count_10m,
            unique_dst_ports_5m=unique_dst_ports_5m,
            login_failures_5m=failures_5m,
            http_error_ratio_5m=round(http_error_ratio, 3),
            dns_query_length=len(domain or ""),
            off_hours=now.hour < 6 or now.hour >= 23,
            hits_blacklist=False,
            is_whitelisted=is_ip_whitelisted(event.src_ip) or is_domain_whitelisted(domain),
            asset_importance=get_asset_importance(event.dst_ip),
            signature_severity=event.severity,
        )

    def _track_event(self, src_key: str, event: SecurityEvent) -> None:
        self._src_events[src_key].append((event.ts, event.event_type, event.src_port, event.dst_port))

    def _cleanup(self, src_key: str, now: datetime) -> None:
        event_cutoff = now - timedelta(minutes=10)
        while self._src_events[src_key] and self._src_events[src_key][0][0] < event_cutoff:
            self._src_events[src_key].popleft()

        http_cutoff = now - timedelta(minutes=5)
        while self._src_http_status[src_key] and self._src_http_status[src_key][0][0] < http_cutoff:
            self._src_http_status[src_key].popleft()

        while self._src_auth_failures[src_key] and self._src_auth_failures[src_key][0] < http_cutoff:
            self._src_auth_failures[src_key].popleft()

    @staticmethod
    def _is_auth_failure(event: SecurityEvent) -> bool:
        signature = (event.signature or "").lower()
        category = (event.category or "").lower()
        return any(
            keyword in signature or keyword in category
            for keyword in ("ssh", "brute", "auth", "login failed", "authentication")
        )
