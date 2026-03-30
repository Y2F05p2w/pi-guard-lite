from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any


def parse_vcgencmd_temp(output: str) -> float | None:
    output = output.strip()
    if "temp=" not in output:
        return None
    try:
        value = output.split("temp=", 1)[1].split("'")[0]
        return float(value)
    except Exception:
        return None


def read_thermal_zone_temp(path: str | Path = "/sys/class/thermal/thermal_zone0/temp") -> float | None:
    source = Path(path)
    if not source.exists():
        return None
    try:
        raw = source.read_text(encoding="utf-8").strip()
        return round(float(raw) / 1000.0, 2)
    except Exception:
        return None


def collect_runtime_report() -> dict[str, Any]:
    return {
        "host": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "paths": {
            "cwd": os.getcwd(),
        },
        "binaries": {
            "python3": shutil.which("python3") or shutil.which("python"),
            "git": shutil.which("git"),
            "fluent-bit": shutil.which("fluent-bit"),
            "suricata": shutil.which("suricata"),
        },
        "systemd": {
            "available": shutil.which("systemctl") is not None,
            "services": _collect_service_states(),
        },
        "resources": {
            "disk": _disk_usage(),
            "temperature_c": _collect_temperature(),
        },
    }


def _disk_usage() -> dict[str, Any]:
    usage = shutil.disk_usage(Path.cwd())
    total = usage.total
    used = usage.used
    percent = round((used / total) * 100, 2) if total else 0.0
    return {
        "total": total,
        "used": used,
        "free": usage.free,
        "used_percent": percent,
    }


def _collect_temperature() -> float | None:
    vcgencmd = shutil.which("vcgencmd")
    if vcgencmd:
        try:
            completed = subprocess.run(
                [vcgencmd, "measure_temp"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            value = parse_vcgencmd_temp(completed.stdout)
            if value is not None:
                return value
        except Exception:
            pass
    return read_thermal_zone_temp()


def _collect_service_states() -> dict[str, str]:
    services = (
        "pi-guard-lite.service",
        "pi-guard-lite-pipeline.service",
        "pi-guard-lite-fluentbit.service",
        "pi-guard-lite-release-expired.timer",
    )
    if shutil.which("systemctl") is None:
        return {name: "systemctl-unavailable" for name in services}
    states: dict[str, str] = {}
    for name in services:
        try:
            completed = subprocess.run(
                ["systemctl", "is-active", name],
                capture_output=True,
                text=True,
                timeout=3,
            )
            state = (completed.stdout or completed.stderr).strip() or "unknown"
            states[name] = state
        except Exception:
            states[name] = "unknown"
    return states


def report_as_json() -> str:
    return json.dumps(collect_runtime_report(), ensure_ascii=False, indent=2)
