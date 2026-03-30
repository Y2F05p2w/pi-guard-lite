from __future__ import annotations

import json
from typing import Any

from app.common.db import get_connection
from app.common.schemas import FeatureVector, RiskScoreResult, SecurityEvent


def insert_event(event: SecurityEvent) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO event (
                ts, source, src_ip, dst_ip, event_type, severity, raw_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.ts.isoformat(),
                event.source,
                event.src_ip,
                event.dst_ip,
                event.event_type,
                event.severity,
                event.raw_path,
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def insert_feature(event_id: int, features: FeatureVector) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO feature (event_id, feature_json) VALUES (?, ?)",
            (event_id, json.dumps(features.model_dump(), ensure_ascii=False)),
        )
        conn.commit()


def update_event_scores(event_id: int, result: RiskScoreResult) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE event
            SET anomaly_score = ?, ml_score = ?, risk_score = ?, risk_level = ?
            WHERE id = ?
            """,
            (result.anomaly_score, result.ml_score, result.risk_score, result.risk_level, event_id),
        )
        conn.commit()


def insert_audit_log(category: str, action: str, detail: dict[str, Any] | str) -> None:
    raw_detail = detail if isinstance(detail, str) else json.dumps(detail, ensure_ascii=False)
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO audit_log (category, action, detail) VALUES (?, ?, ?)",
            (category, action, raw_detail),
        )
        conn.commit()


def list_events(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, ts, source, src_ip, dst_ip, event_type, severity,
                   anomaly_score, ml_score, risk_score, risk_level, raw_path
            FROM event
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
