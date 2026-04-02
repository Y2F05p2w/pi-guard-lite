from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.common.db import init_db
from app.common.logger import setup_logging
from app.detector.evaluation import evaluate_active_models, evaluate_model_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Pi-Guard Lite models")
    parser.add_argument("dataset", help="CSV dataset path")
    parser.add_argument("--model-name", choices=["anomaly", "classifier"])
    parser.add_argument("--model-path", help="Specific model file to evaluate")
    parser.add_argument("--version", default="")
    parser.add_argument("--no-persist", action="store_true")
    args = parser.parse_args()

    setup_logging()
    init_db()
    persist = not args.no_persist

    if args.model_name and args.model_path:
        result = evaluate_model_file(
            model_name=args.model_name,
            model_path=args.model_path,
            dataset_path=args.dataset,
            version=args.version or None,
            persist=persist,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    results = evaluate_active_models(args.dataset, persist=persist)
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
