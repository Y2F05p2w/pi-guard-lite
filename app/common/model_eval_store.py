from __future__ import annotations

import json
from typing import Any

from app.common.db import get_connection
from app.common.schemas import ModelEvaluationRecord


def insert_model_evaluation(record: ModelEvaluationRecord) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO model_evaluation (
                model_name, version, dataset_path, total_samples,
                positive_samples, negative_samples, accuracy, precision,
                recall, fpr, threshold, confusion_json, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.model_name,
                record.version,
                record.dataset_path,
                record.total_samples,
                record.positive_samples,
                record.negative_samples,
                record.accuracy,
                record.precision,
                record.recall,
                record.fpr,
                record.threshold,
                json.dumps(record.confusion, ensure_ascii=False),
                record.notes,
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def list_model_evaluations(model_name: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    query = """
        SELECT id, model_name, version, dataset_path, total_samples,
               positive_samples, negative_samples, accuracy, precision,
               recall, fpr, threshold, confusion_json, notes, created_at
        FROM model_evaluation
    """
    params: tuple[Any, ...] = ()
    if model_name:
        query += " WHERE model_name = ?"
        params = (model_name,)
    query += " ORDER BY id DESC LIMIT ?"
    params = (*params, limit)
    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["confusion_json"] = json.loads(item["confusion_json"] or "{}")
        results.append(item)
    return results
