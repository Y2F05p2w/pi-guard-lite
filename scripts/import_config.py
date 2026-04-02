from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Import Pi-Guard Lite config files")
    parser.add_argument("source_dir", help="Directory containing yaml config files")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    config_dir = root / "config"
    source_dir = Path(args.source_dir)
    if not source_dir.is_absolute():
        source_dir = root / source_dir
    if not source_dir.exists():
        raise FileNotFoundError(source_dir)

    imported = []
    for path in source_dir.glob("*.yaml"):
        target = config_dir / path.name
        shutil.copy2(path, target)
        imported.append(str(target))

    print(json.dumps({"imported": imported, "source_dir": str(source_dir)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
