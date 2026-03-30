from __future__ import annotations

import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

from app.common.schemas import FeatureVector
from app.detector.ml_engine import MLInferenceEngine
from app.detector.training import load_training_dataset, train_models
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class TrainingPipelineTestCase(unittest.TestCase):
    def setUp(self) -> None:
        setup_isolated_db(self.__class__.__name__)
        self.tmpdir = Path(__file__).parent / "_tmp_training"
        if self.tmpdir.exists():
            shutil.rmtree(self.tmpdir, ignore_errors=True)
        self.tmpdir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        cleanup_isolated_db()

    def test_load_training_dataset(self) -> None:
        path = Path(__file__).parent / "samples" / "training_features.csv"
        x, y = load_training_dataset(path)
        self.assertEqual(len(x), 10)
        self.assertEqual(len(y), 10)
        self.assertEqual(len(x[0]), 15)

    def test_train_models_and_infer(self) -> None:
        dataset = Path(__file__).parent / "samples" / "training_features.csv"
        anomaly = self.tmpdir / "anomaly.joblib"
        classifier = self.tmpdir / "classifier.joblib"
        result = train_models(dataset, anomaly, classifier)
        self.assertTrue(Path(result["anomaly_output"]).exists())
        self.assertTrue(Path(result["classifier_output"]).exists())

        settings = {
            "ml": {
                "enabled": True,
                "anomaly_model_path": str(anomaly),
                "classifier_model_path": str(classifier),
            }
        }
        with patch("app.detector.ml_engine.get_settings", return_value=settings):
            engine = MLInferenceEngine()
            features = FeatureVector(
                event_type="suricata.http",
                src_ip="203.0.113.10",
                request_count_1m=24,
                same_event_count_10m=6,
                unique_dst_ports_5m=10,
                login_failures_5m=8,
                http_error_ratio_5m=0.8,
                dns_query_length=52,
                asset_importance=5,
                signature_severity=3,
                baseline_score=14,
                known_source=False,
                known_event_type=False,
                new_destination_ip=True,
                new_destination_port=True,
            )
            inference = engine.infer(features)
            self.assertTrue(inference.model_loaded)
            self.assertGreater(inference.classifier_score, 0)


if __name__ == "__main__":
    unittest.main()
