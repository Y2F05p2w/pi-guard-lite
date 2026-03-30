from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Iterator

from app.common.schemas import RawInputEvent


logger = logging.getLogger(__name__)


class SuricataFileReader:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def read_existing(self) -> Iterator[RawInputEvent]:
        if not self.path.exists():
            logger.warning("suricata input file not found: %s", self.path)
            return
        with self.path.open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("invalid json at %s:%s", self.path, lineno)
                    continue
                yield RawInputEvent(source="suricata", payload=payload, raw_path=str(self.path))

    def tail(self, poll_interval: float = 1.0) -> Iterator[RawInputEvent]:
        if not self.path.exists():
            logger.warning("suricata input file not found: %s", self.path)
            return
        with self.path.open("r", encoding="utf-8") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(poll_interval)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("invalid json while tailing %s", self.path)
                    continue
                yield RawInputEvent(source="suricata", payload=payload, raw_path=str(self.path))
