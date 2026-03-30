from __future__ import annotations

import json
from datetime import UTC, datetime

from app.common.db import get_connection
from app.common.schemas import FeatureVector, SecurityEvent


class BaselineEngine:
    def build_profile_key(self, event: SecurityEvent) -> str:
        return event.src_ip or f"{event.source}:unknown"

    def enrich(self, event: SecurityEvent, features: FeatureVector) -> FeatureVector:
        profile_key = self.build_profile_key(event)
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM baseline_profile WHERE profile_key = ?",
                (profile_key,),
            ).fetchone()

            if row is None:
                self._create_profile(conn, profile_key, event)
                features.known_source = False
                features.known_event_type = False
                features.new_destination_ip = bool(event.dst_ip)
                features.new_destination_port = event.dst_port is not None
                features.baseline_score = 30.0
                conn.commit()
                return features

            event_types = json.loads(row["event_types_json"] or "{}")
            active_hours = set(json.loads(row["active_hours_json"] or "[]"))
            dst_ips = set(json.loads(row["dst_ips_json"] or "[]"))
            dst_ports = set(json.loads(row["dst_ports_json"] or "[]"))

            score = 0.0
            features.known_source = True

            if event.event_type in event_types:
                features.known_event_type = True
            else:
                features.known_event_type = False
                score += 12

            current_hour = event.ts.hour
            if active_hours and current_hour not in active_hours:
                score += 6

            if event.dst_ip and event.dst_ip not in dst_ips:
                features.new_destination_ip = True
                score += 5

            if event.dst_port is not None and str(event.dst_port) not in dst_ports:
                features.new_destination_port = True
                score += 4

            features.baseline_score = score
            self._update_profile(conn, row, event)
            conn.commit()
            return features

    def _create_profile(self, conn, profile_key: str, event: SecurityEvent) -> None:
        event_types = {event.event_type: 1}
        hours = [event.ts.hour]
        dst_ips = [event.dst_ip] if event.dst_ip else []
        dst_ports = [str(event.dst_port)] if event.dst_port is not None else []
        conn.execute(
            """
            INSERT OR IGNORE INTO baseline_profile (
                profile_key, total_events, event_types_json, active_hours_json,
                dst_ips_json, dst_ports_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                profile_key,
                1,
                json.dumps(event_types, ensure_ascii=False),
                json.dumps(hours, ensure_ascii=False),
                json.dumps(dst_ips, ensure_ascii=False),
                json.dumps(dst_ports, ensure_ascii=False),
                datetime.now(UTC).isoformat(),
            ),
        )

    def _update_profile(self, conn, row, event: SecurityEvent) -> None:
        event_types = json.loads(row["event_types_json"] or "{}")
        active_hours = set(json.loads(row["active_hours_json"] or "[]"))
        dst_ips = set(json.loads(row["dst_ips_json"] or "[]"))
        dst_ports = set(json.loads(row["dst_ports_json"] or "[]"))

        event_types[event.event_type] = int(event_types.get(event.event_type, 0)) + 1
        active_hours.add(event.ts.hour)
        if event.dst_ip:
            dst_ips.add(event.dst_ip)
        if event.dst_port is not None:
            dst_ports.add(str(event.dst_port))

        conn.execute(
            """
            UPDATE baseline_profile
            SET total_events = ?,
                event_types_json = ?,
                active_hours_json = ?,
                dst_ips_json = ?,
                dst_ports_json = ?,
                updated_at = ?
            WHERE profile_key = ?
            """,
            (
                int(row["total_events"]) + 1,
                json.dumps(event_types, ensure_ascii=False),
                json.dumps(sorted(active_hours), ensure_ascii=False),
                json.dumps(sorted(dst_ips), ensure_ascii=False),
                json.dumps(sorted(dst_ports), ensure_ascii=False),
                datetime.now(UTC).isoformat(),
                row["profile_key"],
            ),
        )
