from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.common.config import PROJECT_ROOT, get_settings, resolve_path


def run_preflight_checks(project_root: Path | None = None) -> dict[str, Any]:
    project_root = project_root or PROJECT_ROOT
    settings = get_settings()
    checks: list[dict[str, Any]] = []

    checks.extend(_check_runtime_paths(project_root, settings))
    checks.extend(_check_model_paths(settings))
    checks.extend(_check_executor_config(project_root))
    checks.extend(_check_fluentbit_configs(project_root))
    checks.extend(_check_scan_listener_config(settings))
    checks.extend(_check_systemd_units(project_root))

    passed = len([item for item in checks if item["status"] == "pass"])
    failed = len([item for item in checks if item["status"] == "fail"])
    warnings = len([item for item in checks if item["status"] == "warn"])
    return {
        "summary": {
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "total": len(checks),
        },
        "checks": checks,
    }


def _check_runtime_paths(project_root: Path, settings: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for key in ("database", "logs_dir", "raw_data_dir", "templates_dir"):
        raw = settings.get("paths", {}).get(key)
        if not raw:
            result.append(_check("paths", key, "fail", "missing path config"))
            continue
        path = resolve_path(raw)
        exists = path.exists() or key == "database"
        result.append(
            _check(
                "paths",
                key,
                "pass" if exists else "warn",
                f"path={path}",
            )
        )
    return result


def _check_model_paths(settings: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    ml_cfg = settings.get("ml", {})
    enabled = bool(ml_cfg.get("enabled", False))
    for key in ("anomaly_model_path", "classifier_model_path"):
        raw = ml_cfg.get(key)
        if not raw:
            result.append(_check("ml", key, "warn", "not configured"))
            continue
        path = resolve_path(raw)
        if path.exists():
            result.append(_check("ml", key, "pass", f"found {path}"))
        else:
            level = "warn" if not enabled else "fail"
            result.append(_check("ml", key, level, f"missing {path}"))
    return result


def _check_executor_config(project_root: Path) -> list[dict[str, Any]]:
    path = project_root / "config" / "executor.yaml"
    if not path.exists():
        return [_check("executor", "executor.yaml", "fail", "config file missing")]

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    executor = data.get("executor", {})
    result = []
    for key in ("host", "username", "block_command", "unblock_command"):
        value = executor.get(key)
        result.append(
            _check(
                "executor",
                key,
                "pass" if value else "warn",
                str(value) if value else "empty",
            )
        )
    result.append(
        _check(
            "executor",
            "dry_run",
            "warn" if executor.get("dry_run", True) else "pass",
            f"dry_run={executor.get('dry_run', True)}",
        )
    )
    return result


def _check_fluentbit_configs(project_root: Path) -> list[dict[str, Any]]:
    result = []
    for name in ("fluent-bit.conf", "fluent-bit-rpi.conf"):
        path = project_root / "config" / name
        result.append(
            _check(
                "fluentbit",
                name,
                "pass" if path.exists() else "fail",
                f"path={path}",
            )
        )
    bridge = project_root / "scripts" / "start_fluentbit_bridge.sh"
    result.append(
        _check(
            "fluentbit",
            "bridge_script",
            "pass" if bridge.exists() else "fail",
            f"path={bridge}",
        )
    )
    return result


def _check_scan_listener_config(settings: dict[str, Any]) -> list[dict[str, Any]]:
    scan_cfg = settings.get("scan_listener", {})
    results = [
        _check("scan_listener", "enabled", "warn" if not scan_cfg.get("enabled", False) else "pass", f"enabled={scan_cfg.get('enabled', False)}"),
        _check("scan_listener", "auto_start_with_web", "pass" if scan_cfg.get("auto_start_with_web", True) else "warn", f"auto_start_with_web={scan_cfg.get('auto_start_with_web', True)}"),
        _check("scan_listener", "bind_host", "pass" if scan_cfg.get("bind_host") else "warn", str(scan_cfg.get("bind_host", ""))),
        _check("scan_listener", "report_host", "pass" if scan_cfg.get("report_host") else "warn", str(scan_cfg.get("report_host", ""))),
        _check("scan_listener", "ports", "pass" if scan_cfg.get("ports") else "warn", str(scan_cfg.get("ports", ""))),
    ]
    script = PROJECT_ROOT / "scripts" / "run_scan_listener_service.py"
    results.append(
        _check(
            "scan_listener",
            "service_script",
            "pass" if script.exists() else "fail",
            f"path={script}",
        )
    )
    return results


def _check_systemd_units(project_root: Path) -> list[dict[str, Any]]:
    result = []
    for name in (
        "pi-guard-lite.service",
        "pi-guard-lite-pipeline.service",
        "pi-guard-lite-input-supervisor.service",
        "pi-guard-lite-fluentbit.service",
        "pi-guard-lite-scan-listener.service",
        "pi-guard-lite-release-expired.service",
        "pi-guard-lite-release-expired.timer",
    ):
        path = project_root / "systemd" / name
        result.append(
            _check(
                "systemd",
                name,
                "pass" if path.exists() else "fail",
                f"path={path}",
            )
        )
    return result


def _check(category: str, name: str, status: str, detail: str) -> dict[str, str]:
    return {
        "category": category,
        "name": name,
        "status": status,
        "detail": detail,
    }
