from __future__ import annotations

import pickle
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.detector.demo_models import DemoAnomalyModel, DemoClassifierModel


def main() -> None:
    models_dir = PROJECT_ROOT / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    anomaly_path = models_dir / "anomaly_model.pkl"
    classifier_path = models_dir / "classifier_model.pkl"

    with anomaly_path.open("wb") as f:
        pickle.dump(DemoAnomalyModel(), f)
    with classifier_path.open("wb") as f:
        pickle.dump(DemoClassifierModel(), f)

    print(f"created: {anomaly_path}")
    print(f"created: {classifier_path}")


if __name__ == "__main__":
    main()
