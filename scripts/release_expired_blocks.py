from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.common.db import init_db
from app.common.logger import setup_logging
from app.policy.service import PolicyService


def main() -> None:
    setup_logging()
    init_db()
    service = PolicyService()
    results = service.release_expired()
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
