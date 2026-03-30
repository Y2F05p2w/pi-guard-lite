from __future__ import annotations

import json
from typing import Any

from app.common.db import get_connection
from app.common.schemas import AnalysisResult, FeatureVector, RiskScoreResult, SecurityEvent


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


def upsert_analysis_result(event_id: int, result: AnalysisResult) -> None:
    graph_json = {
        "nodes": [item.model_dump() for item in result.graph_nodes],
        "edges": [item.model_dump() for item in result.graph_edges],
    }
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO analysis_result (
                event_id, findings_json, mitre_json, graph_json, impacted_assets_json, summary
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
                findings_json = excluded.findings_json,
                mitre_json = excluded.mitre_json,
                graph_json = excluded.graph_json,
                impacted_assets_json = excluded.impacted_assets_json,
                summary = excluded.summary
            """,
            (
                event_id,
                json.dumps([item.model_dump() for item in result.findings], ensure_ascii=False),
                json.dumps([item.model_dump() for item in result.techniques], ensure_ascii=False),
                json.dumps(graph_json, ensure_ascii=False),
                json.dumps(result.impacted_assets, ensure_ascii=False),
                result.summary,
            ),
        )
        conn.commit()


def get_analysis_result(event_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT event_id, findings_json, mitre_json, graph_json, impacted_assets_json, summary, created_at
            FROM analysis_result
            WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()
    return dict(row) if row else None
