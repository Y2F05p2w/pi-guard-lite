from __future__ import annotations

import math
import pickle
from pathlib import Path
from typing import Any

from app.common.config import get_settings
from app.common.model_eval_store import insert_model_evaluation
from app.common.schemas import ModelEvaluationRecord
from app.detector.ml_features import FEATURE_COLUMNS
from app.detector.model_manager import ModelManager
from app.detector.training import load_training_dataset


def evaluate_model_file(
    *,
    model_name: str,
    model_path: str | Path,
    dataset_path: str | Path,
    version: str | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    model_file = Path(model_path)
    dataset_file = Path(dataset_path)
    with model_file.open("rb") as f:
        model = pickle.load(f)

    x, y = load_training_dataset(dataset_file)
    settings = get_settings()
    eval_cfg = settings.get("ml", {}).get("evaluation", {})
    threshold = _resolve_threshold(model_name=model_name, model=model, vectors=x, eval_cfg=eval_cfg)
    predictions = _predict_labels(model_name=model_name, model=model, vectors=x, threshold=threshold)
    metrics = _compute_metrics(y_true=y, y_pred=predictions)

    record = ModelEvaluationRecord(
        model_name=model_name,
        version=version,
        dataset_path=str(dataset_file),
        total_samples=metrics["total"],
        positive_samples=metrics["positive_samples"],
        negative_samples=metrics["negative_samples"],
        accuracy=metrics["accuracy"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        fpr=metrics["fpr"],
        threshold=threshold,
        confusion=metrics["confusion"],
        notes=f"features={','.join(FEATURE_COLUMNS)}",
    )
    evaluation_id = insert_model_evaluation(record) if persist else None

    return {
        "evaluation_id": evaluation_id,
        "model_name": model_name,
        "version": version,
        "dataset_path": str(dataset_file),
        "threshold": threshold,
        **metrics,
    }


def evaluate_active_models(dataset_path: str | Path, persist: bool = True) -> list[dict[str, Any]]:
    manager = ModelManager()
    status = manager.get_status()
    results = []
    for model_name, active in status.get("active_versions", {}).items():
        results.append(
            evaluate_model_file(
                model_name=model_name,
                model_path=active["file_path"],
                dataset_path=dataset_path,
                version=active["version"],
                persist=persist,
            )
        )
    return results


def _resolve_threshold(*, model_name: str, model: Any, vectors: list[list[float]], eval_cfg: dict[str, Any]) -> float:
    if model_name == "classifier":
        return float(eval_cfg.get("classifier_threshold", 0.5))
    percentile = float(eval_cfg.get("anomaly_percentile", 20))
    scores = _score_anomaly_model(model, vectors)
    return _percentile(scores, percentile)


def _predict_labels(*, model_name: str, model: Any, vectors: list[list[float]], threshold: float) -> list[int]:
    if model_name == "classifier":
        scores = _score_classifier_model(model, vectors)
        return [1 if score >= threshold else 0 for score in scores]
    scores = _score_anomaly_model(model, vectors)
    return [1 if score <= threshold else 0 for score in scores]


def _score_classifier_model(model: Any, vectors: list[list[float]]) -> list[float]:
    if hasattr(model, "predict_proba"):
        rows = model.predict_proba(vectors)
        return [float(row[1]) for row in rows]
    if hasattr(model, "predict"):
        return [float(value) for value in model.predict(vectors)]
    raise ValueError("classifier model does not support predict_proba/predict")


def _score_anomaly_model(model: Any, vectors: list[list[float]]) -> list[float]:
    if hasattr(model, "score_samples"):
        return [float(value) for value in model.score_samples(vectors)]
    if hasattr(model, "decision_function"):
        return [float(value) for value in model.decision_function(vectors)]
    raise ValueError("anomaly model does not support score_samples/decision_function")


def _compute_metrics(*, y_true: list[int], y_pred: list[int]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for truth, pred in zip(y_true, y_pred):
        if truth == 1 and pred == 1:
            tp += 1
        elif truth == 0 and pred == 1:
            fp += 1
        elif truth == 0 and pred == 0:
            tn += 1
        else:
            fn += 1

    total = len(y_true)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    accuracy = (tp + tn) / max(total, 1)
    fpr = fp / max(fp + tn, 1)
    return {
        "total": total,
        "positive_samples": sum(1 for item in y_true if item == 1),
        "negative_samples": sum(1 for item in y_true if item == 0),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "fpr": round(fpr, 4),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    percentile = min(max(percentile, 0.0), 100.0)
    index = int(math.floor((percentile / 100.0) * max(len(ordered) - 1, 0)))
    return float(ordered[index])
