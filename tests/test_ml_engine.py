from __future__ import annotations

import pickle
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.common.schemas import FeatureVector
from app.detector.ml_engine import MLInferenceEngine
from tests.support_models import MockAnomalyModel, MockClassifierModel


class MLInferenceEngineTestCase(unittest.TestCase):
    def test_disabled_ml_returns_empty_result(self) -> None:
        with patch("app.detector.ml_engine.get_settings", return_value={"ml": {"enabled": False}}):
            engine = MLInferenceEngine()
            result = engine.infer(FeatureVector(event_type="suricata.http", src_ip="203.0.113.9"))
            self.assertFalse(result.enabled)
            self.assertFalse(result.model_loaded)

    def test_loads_pickled_models_and_scores(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            anomaly_path = Path(tmpdir) / "anomaly.pkl"
            classifier_path = Path(tmpdir) / "classifier.pkl"
            with anomaly_path.open("wb") as f:
                pickle.dump(MockAnomalyModel(), f)
            with classifier_path.open("wb") as f:
                pickle.dump(MockClassifierModel(), f)

            settings = {
                "ml": {
                    "enabled": True,
                    "anomaly_model_path": str(anomaly_path),
                    "classifier_model_path": str(classifier_path),
                }
            }
            with patch("app.detector.ml_engine.get_settings", return_value=settings):
                engine = MLInferenceEngine()
                features = FeatureVector(
                    event_type="suricata.http",
                    src_ip="203.0.113.10",
                    request_count_1m=30,
                    login_failures_5m=10,
                    unique_dst_ports_5m=5,
                    baseline_score=8,
                )
                result = engine.infer(features)
                self.assertTrue(result.enabled)
                self.assertTrue(result.model_loaded)
                self.assertGreater(result.anomaly_score, 0)
                self.assertGreater(result.classifier_score, 0)


if __name__ == "__main__":
    unittest.main()
