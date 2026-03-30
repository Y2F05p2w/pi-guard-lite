from __future__ import annotations

import pickle
from typing import Any

from app.common.config import get_settings, resolve_path
from app.common.schemas import FeatureVector, MLInferenceResult
from app.detector.ml_features import feature_vector_to_list


class MLInferenceEngine:
    def __init__(self) -> None:
        settings = get_settings()
        self.config = settings.get("ml", {})
        self.enabled = bool(self.config.get("enabled", False))
        self.anomaly_model = self._load_model(self.config.get("anomaly_model_path"))
        self.classifier_model = self._load_model(self.config.get("classifier_model_path"))

    def infer(self, features: FeatureVector) -> MLInferenceResult:
        if not self.enabled:
            return MLInferenceResult(enabled=False, model_loaded=False, reason="ml disabled")

        vector = [feature_vector_to_list(features)]
        anomaly_score = 0.0
        classifier_score = 0.0
        loaded = False
        reasons: list[str] = []

        if self.anomaly_model is not None:
            loaded = True
            anomaly_score = self._run_anomaly_model(self.anomaly_model, vector)
            reasons.append("anomaly model used")

        if self.classifier_model is not None:
            loaded = True
            classifier_score = self._run_classifier_model(self.classifier_model, vector)
            reasons.append("classifier model used")

        if not loaded:
            return MLInferenceResult(
                enabled=True,
                model_loaded=False,
                reason="ml enabled but no model file loaded",
            )

        return MLInferenceResult(
            enabled=True,
            model_loaded=loaded,
            anomaly_score=round(max(0.0, min(100.0, anomaly_score)), 2),
            classifier_score=round(max(0.0, min(100.0, classifier_score)), 2),
            reason=", ".join(reasons),
        )

    def _load_model(self, raw_path: str | None) -> Any | None:
        if not self.enabled or not raw_path:
            return None
        path = resolve_path(raw_path)
        if not path.exists():
            return None

        if path.suffix == ".joblib":
            try:
                import joblib  # type: ignore

                return joblib.load(path)
            except Exception:
                try:
                    with path.open("rb") as f:
                        return pickle.load(f)
                except Exception:
                    return None

        try:
            with path.open("rb") as f:
                return pickle.load(f)
        except Exception:
            return None

    def _run_anomaly_model(self, model: Any, vector: list[list[float]]) -> float:
        if hasattr(model, "score_samples"):
            scores = model.score_samples(vector)
            score = float(scores[0])
            return min(100.0, max(0.0, 50.0 - score * 10.0))
        if hasattr(model, "decision_function"):
            scores = model.decision_function(vector)
            score = float(scores[0])
            return min(100.0, max(0.0, 50.0 - score * 10.0))
        if hasattr(model, "predict"):
            pred = model.predict(vector)[0]
            return 90.0 if int(pred) in (-1, 1) else 0.0
        return 0.0

    def _run_classifier_model(self, model: Any, vector: list[list[float]]) -> float:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(vector)
            return float(probs[0][-1] * 100.0)
        if hasattr(model, "predict"):
            pred = model.predict(vector)[0]
            return 90.0 if int(pred) == 1 else 10.0
        return 0.0
