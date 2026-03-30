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


def main() -> None:
    parser = argparse.ArgumentParser(description="Import model file into Pi-Guard Lite")
    parser.add_argument("model_name", choices=["anomaly", "classifier"])
    parser.add_argument("source_path")
    parser.add_argument("--version", default=None)
    parser.add_argument("--no-activate", action="store_true")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    init_db()
    manager = ModelManager()

    if args.list:
        print(json.dumps(manager.list_versions(args.model_name), ensure_ascii=False, indent=2))
        return

    result = manager.import_model(
        model_name=args.model_name,
        source_path=args.source_path,
        version=args.version,
        activate=not args.no_activate,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
