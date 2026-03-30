from __future__ import annotations

import pickle
import shutil
import unittest
from pathlib import Path

from app.common.db import get_connection, init_db
from app.detector.demo_models import DemoAnomalyModel
from app.detector.model_manager import ModelManager


class ModelManagerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        init_db()
        with get_connection() as conn:
            conn.execute("DELETE FROM model_version")
            conn.commit()

        self.imported_dir = Path("models/imported/anomaly")
        if self.imported_dir.exists():
            for item in self.imported_dir.glob("*"):
                item.unlink()
        self.tmpdir = Path(__file__).parent / "_tmp_model_manager"
        if self.tmpdir.exists():
            shutil.rmtree(self.tmpdir, ignore_errors=True)
        self.tmpdir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_import_and_activate_model(self) -> None:
        source = self.tmpdir / "demo.pkl"
        with source.open("wb") as f:
            pickle.dump(DemoAnomalyModel(), f)

        manager = ModelManager()
        result = manager.import_model("anomaly", str(source), version="unit-test", activate=True)
        self.assertEqual(result["model_name"], "anomaly")
        self.assertEqual(result["version"], "unit-test")

        versions = manager.list_versions("anomaly")
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0]["version"], "unit-test")
        self.assertEqual(versions[0]["is_active"], 1)

        grouped = manager.grouped_versions()
        self.assertIn("anomaly", grouped)
        self.assertEqual(grouped["anomaly"][0]["version"], "unit-test")

        status = manager.get_status()
        self.assertIn("anomaly", status["active_versions"])
        self.assertEqual(status["active_versions"]["anomaly"]["version"], "unit-test")

        active_target = Path("models/anomaly_model.pkl")
        self.assertTrue(active_target.exists())


if __name__ == "__main__":
    unittest.main()
