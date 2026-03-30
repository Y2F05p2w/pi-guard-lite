from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Iterator

from app.common.schemas import RawInputEvent


logger = logging.getLogger(__name__)


class TextLogFileReader:
    def __init__(self, path: str | Path, source: str) -> None:
        self.path = Path(path)
        self.source = source

    def read_existing(self) -> Iterator[RawInputEvent]:
        if not self.path.exists():
            logger.warning("system log file not found: %s", self.path)
            return
        with self.path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line:
                    continue
                yield RawInputEvent(
                    source=self.source,
                    payload={"message": line},
                    raw_path=str(self.path),
                )

    def tail(self, poll_interval: float = 1.0) -> Iterator[RawInputEvent]:
        if not self.path.exists():
            logger.warning("system log file not found: %s", self.path)
            return
        with self.path.open("r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(poll_interval)
                    continue
                line = line.rstrip("\r\n")
                if not line:
                    continue
                yield RawInputEvent(
                    source=self.source,
                    payload={"message": line},
                    raw_path=str(self.path),
                )
