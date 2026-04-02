from __future__ import annotations

import unittest
from pathlib import Path

from app.common.db import init_db
from app.common.model_eval_store import list_model_evaluations
from app.detector.evaluation import evaluate_model_file
from app.detector.training import train_models
from tests.test_helpers import cleanup_isolated_db, cleanup_temp_dirs, setup_isolated_db


class ModelEvaluationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        setup_isolated_db(self.__class__.__name__)
        init_db()
        self.temp_dir = Path(__file__).parent / "_tmp_models_eval"
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        cleanup_isolated_db()
        cleanup_temp_dirs(self.temp_dir)

    def test_evaluate_model_file(self) -> None:
        dataset = Path(__file__).parent / "samples" / "training_features.csv"
        anomaly_path = self.temp_dir / "anomaly.pkl"
        classifier_path = self.temp_dir / "classifier.pkl"
        train_models(dataset, anomaly_path, classifier_path)

        result = evaluate_model_file(
            model_name="classifier",
            model_path=classifier_path,
            dataset_path=dataset,
            version="eval-v1",
            persist=True,
        )

        self.assertIn("accuracy", result)
        self.assertGreaterEqual(result["accuracy"], 0)
        evaluations = list_model_evaluations("classifier", limit=10)
        self.assertEqual(len(evaluations), 1)
        self.assertEqual(evaluations[0]["version"], "eval-v1")


if __name__ == "__main__":
    unittest.main()
