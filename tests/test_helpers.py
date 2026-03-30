from __future__ import annotations

import os
import shutil
from pathlib import Path


def setup_isolated_db(name: str) -> Path:
    temp_root = Path(__file__).parent / "_tmp_db"
    temp_root.mkdir(parents=True, exist_ok=True)
    db_path = temp_root / f"{name}.db"
    if db_path.exists():
        db_path.unlink()
    os.environ["PI_GUARD_DB_PATH"] = str(db_path)
    return db_path


def cleanup_isolated_db() -> None:
    os.environ.pop("PI_GUARD_DB_PATH", None)


def cleanup_temp_dirs(*paths: Path) -> None:
    for path in paths:
        if path.exists():
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink(missing_ok=True)
