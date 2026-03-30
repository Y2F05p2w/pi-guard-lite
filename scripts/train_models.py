from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.common.db import init_db
from app.detector.model_manager import ModelManager
from app.detector.training import train_models


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Pi-Guard Lite models from CSV dataset")
    parser.add_argument("dataset", help="CSV dataset path")
    parser.add_argument("--out-dir", default="models/trained", help="Output directory for trained models")
    parser.add_argument("--version", default=None, help="Optional version to register")
    parser.add_argument("--register", action="store_true", help="Register trained models into model manager")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    anomaly_output = out_dir / "anomaly_model.pkl"
    classifier_output = out_dir / "classifier_model.pkl"

    result = train_models(
        dataset_path=args.dataset,
        anomaly_output_path=anomaly_output,
        classifier_output_path=classifier_output,
    )

    if args.register:
        init_db()
        manager = ModelManager()
        version = args.version or "trained"
        anomaly_record = manager.import_model("anomaly", str(anomaly_output), version=f"{version}-anomaly", activate=True)
        classifier_record = manager.import_model(
            "classifier",
            str(classifier_output),
            version=f"{version}-classifier",
            activate=True,
        )
        result["registered"] = {
            "anomaly": anomaly_record,
            "classifier": classifier_record,
        }

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
