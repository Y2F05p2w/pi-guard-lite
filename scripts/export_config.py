from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Export Pi-Guard Lite config files")
    parser.add_argument("--out-dir", default="backups/config-export", help="Output directory")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    config_dir = root / "config"
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    exported = []
    for path in config_dir.glob("*.yaml"):
        target = out_dir / path.name
        shutil.copy2(path, target)
        exported.append(str(target))

    print(json.dumps({"exported": exported, "out_dir": str(out_dir)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
