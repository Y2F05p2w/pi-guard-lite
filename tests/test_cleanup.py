from __future__ import annotations

import os
import shutil
import tempfile
import time
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from app.common.cleanup import cleanup_runtime_data


class CleanupRuntimeDataTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(dir=str(Path(__file__).parent), prefix="_tmp_cleanup_"))
        self.raw_dir = self.tmpdir / "data" / "raw"
        self.logs_dir = self.tmpdir / "logs"
        self.backups_dir = self.tmpdir / "backups"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_cleanup_removes_old_files(self) -> None:
        old_file = self.raw_dir / "old.jsonl"
        new_file = self.logs_dir / "new.log"
        backup_file = self.backups_dir / "old.tar.gz"

        old_file.write_text("x", encoding="utf-8")
        new_file.write_text("y", encoding="utf-8")
        backup_file.write_text("z", encoding="utf-8")

        old_ts = time.time() - (10 * 24 * 3600)
        os.utime(old_file, (old_ts, old_ts))
        os.utime(backup_file, (old_ts, old_ts))

        settings = {
            "paths": {
                "raw_data_dir": str(self.raw_dir),
                "logs_dir": str(self.logs_dir),
                "backups_dir": str(self.backups_dir),
            },
            "retention": {
                "cleanup_enabled": True,
                "raw_days": 7,
                "log_days": 7,
                "backup_days": 7,
            },
        }
        with patch("app.common.cleanup.get_settings", return_value=settings):
            with patch("app.common.cleanup.resolve_path", side_effect=lambda p: Path(p)):
                result = cleanup_runtime_data(now=datetime.now(UTC))
        self.assertEqual(result["removed_count"], 2)
        self.assertFalse(old_file.exists())
        self.assertFalse(backup_file.exists())
        self.assertTrue(new_file.exists())


if __name__ == "__main__":
    unittest.main()
