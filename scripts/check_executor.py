from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.executor.factory import get_executor


def main() -> None:
    parser = argparse.ArgumentParser(description="Check executor connectivity and optional dry-run action")
    parser.add_argument("--test-ip", default=None, help="Optional IP for test block/unblock")
    parser.add_argument("--ttl", type=int, default=60)
    args = parser.parse_args()

    executor = get_executor()
    payload = {
        "check": executor.check_connection().model_dump(),
    }
    if args.test_ip:
        payload["block"] = executor.block_ip(args.test_ip, args.ttl).model_dump()
        payload["unblock"] = executor.unblock_ip(args.test_ip).model_dump()
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
