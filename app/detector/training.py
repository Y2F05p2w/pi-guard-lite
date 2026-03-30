from __future__ import annotations

import csv
import math
import pickle
from pathlib import Path
from typing import Any

from app.detector.ml_features import FEATURE_COLUMNS


class SimpleAnomalyModel:
    def __init__(self, center: list[float], scale: list[float]) -> None:
        self.center = center
        self.scale = scale

    def score_samples(self, vectors: list[list[float]]) -> list[float]:
        scores: list[float] = []
        for vector in vectors:
            total = 0.0
            for value, mean, scale in zip(vector, self.center, self.scale):
                total += abs(value - mean) / max(scale, 1.0)
            scores.append(-total / max(len(vector), 1))
        return scores


class SimpleClassifierModel:
    def __init__(self, normal_center: list[float], attack_center: list[float]) -> None:
        self.normal_center = normal_center
        self.attack_center = attack_center

    def predict_proba(self, vectors: list[list[float]]) -> list[list[float]]:
        rows: list[list[float]] = []
        for vector in vectors:
            normal_distance = _distance(vector, self.normal_center)
            attack_distance = _distance(vector, self.attack_center)
            attack_score = normal_distance / max(normal_distance + attack_distance, 1e-6)
            attack_score = min(0.99, max(0.01, attack_score))
            rows.append([1 - attack_score, attack_score])
        return rows


def load_training_dataset(path: str | Path) -> tuple[list[list[float]], list[int]]:
    source = Path(path)
    rows_x: list[list[float]] = []
    rows_y: list[int] = []
    with source.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vector = []
            for column in FEATURE_COLUMNS:
                raw = row.get(column, "0")
                if raw is None or raw == "":
                    raw = "0"
                vector.append(float(raw))
            label = int(row.get("label", "0"))
            rows_x.append(vector)
            rows_y.append(label)
    if not rows_x:
        raise ValueError("training dataset is empty")
    return rows_x, rows_y


def train_models(
    dataset_path: str | Path,
    anomaly_output_path: str | Path,
    classifier_output_path: str | Path,
) -> dict[str, Any]:
    x, y = load_training_dataset(dataset_path)
    normal_x = [features for features, label in zip(x, y) if label == 0] or x
    backend = "simple"

    try:
        from sklearn.ensemble import IsolationForest, RandomForestClassifier  # type: ignore

        anomaly_model = IsolationForest(
            n_estimators=100,
            contamination=0.2,
            random_state=42,
        )
        anomaly_model.fit(normal_x)

        classifier_model = RandomForestClassifier(
            n_estimators=120,
            random_state=42,
            class_weight="balanced",
        )
        classifier_model.fit(x, y)
        backend = "sklearn"
    except Exception:
        anomaly_model = SimpleAnomalyModel(
            center=_mean_vector(normal_x),
            scale=_std_vector(normal_x),
        )
        attack_x = [features for features, label in zip(x, y) if label == 1] or x
        classifier_model = SimpleClassifierModel(
            normal_center=_mean_vector(normal_x),
            attack_center=_mean_vector(attack_x),
        )

    anomaly_output = Path(anomaly_output_path)
    classifier_output = Path(classifier_output_path)
    anomaly_output.parent.mkdir(parents=True, exist_ok=True)
    classifier_output.parent.mkdir(parents=True, exist_ok=True)

    with anomaly_output.open("wb") as f:
        pickle.dump(anomaly_model, f)
    with classifier_output.open("wb") as f:
        pickle.dump(classifier_model, f)

    return {
        "rows": len(x),
        "normal_rows": len(normal_x),
        "backend": backend,
        "anomaly_output": str(anomaly_output),
        "classifier_output": str(classifier_output),
    }


def _mean_vector(rows: list[list[float]]) -> list[float]:
    width = len(rows[0])
    means = []
    for i in range(width):
        means.append(sum(row[i] for row in rows) / max(len(rows), 1))
    return means


def _std_vector(rows: list[list[float]]) -> list[float]:
    means = _mean_vector(rows)
    width = len(rows[0])
    stds = []
    for i in range(width):
        variance = sum((row[i] - means[i]) ** 2 for row in rows) / max(len(rows), 1)
        stds.append(max(math.sqrt(variance), 1.0))
    return stds


def _distance(left: list[float], right: list[float]) -> float:
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(left, right)))
