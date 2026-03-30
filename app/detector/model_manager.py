from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.common.config import PROJECT_ROOT, get_settings, resolve_path
from app.common.db import get_connection


class ModelManager:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.models_root = PROJECT_ROOT / "models" / "imported"
        self.models_root.mkdir(parents=True, exist_ok=True)

    def import_model(
        self,
        model_name: str,
        source_path: str,
        version: str | None = None,
        activate: bool = True,
    ) -> dict[str, Any]:
        source = Path(source_path)
        if not source.exists():
            raise FileNotFoundError(f"model file not found: {source}")

        version = version or datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        target_dir = self.models_root / model_name
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = target_dir / f"{version}{source.suffix or '.pkl'}"
        shutil.copy2(source, target_path)

        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO model_version (model_name, version, file_path, is_active)
                VALUES (?, ?, ?, 0)
                """,
                (model_name, version, str(target_path)),
            )
            conn.commit()

        if activate:
            self.activate_model(model_name, version)

        return {
            "model_name": model_name,
            "version": version,
            "file_path": str(target_path),
            "active": activate,
        }

    def activate_model(self, model_name: str, version: str) -> dict[str, Any]:
        record = self._get_version(model_name, version)
        if not record:
            raise ValueError(f"model version not found: {model_name}:{version}")

        active_target = self._get_active_model_target(model_name)
        if active_target is None:
            raise ValueError(f"unsupported model name: {model_name}")

        active_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(record["file_path"], active_target)

        with get_connection() as conn:
            conn.execute("UPDATE model_version SET is_active = 0 WHERE model_name = ?", (model_name,))
            conn.execute(
                "UPDATE model_version SET is_active = 1 WHERE model_name = ? AND version = ?",
                (model_name, version),
            )
            conn.commit()

        return {
            "model_name": model_name,
            "version": version,
            "active_path": str(active_target),
        }

    def list_versions(self, model_name: str | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT id, model_name, version, file_path, is_active, created_at
            FROM model_version
        """
        params: tuple[Any, ...] = ()
        if model_name:
            query += " WHERE model_name = ?"
            params = (model_name,)
        query += " ORDER BY id DESC"

        with get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def _get_version(self, model_name: str, version: str) -> dict[str, Any] | None:
        with get_connection() as conn:
            row = conn.execute(
                """
                SELECT id, model_name, version, file_path, is_active, created_at
                FROM model_version
                WHERE model_name = ? AND version = ?
                """,
                (model_name, version),
            ).fetchone()
        return dict(row) if row else None

    def _get_active_model_target(self, model_name: str) -> Path | None:
        ml_cfg = self.settings.get("ml", {})
        mapping = {
            "anomaly": ml_cfg.get("anomaly_model_path"),
            "classifier": ml_cfg.get("classifier_model_path"),
        }
        raw = mapping.get(model_name)
        if not raw:
            return None
        return resolve_path(raw)
