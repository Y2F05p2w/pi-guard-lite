from __future__ import annotations

import platform
import socket
import subprocess
import time
from urllib.parse import urlparse

import requests

from app.common.config import get_settings
from app.common.schemas import ProbeExecutionResult, ProbeTarget


class ProbeChecker:
    def __init__(self) -> None:
        self.settings = get_settings()

    def load_default_targets(self) -> list[ProbeTarget]:
        targets = []
        for item in self.settings.get("probe", {}).get("default_targets", []):
            if isinstance(item, str):
                targets.append(ProbeTarget(type="http", target=item))
            else:
                targets.append(ProbeTarget(**item))
        return targets

    def run_default_targets(self) -> list[ProbeExecutionResult]:
        return [self.run(target) for target in self.load_default_targets()]

    def run(self, target: ProbeTarget) -> ProbeExecutionResult:
        if target.type == "http":
            return self._http_probe(target)
        if target.type == "tcp":
            return self._tcp_probe(target)
        if target.type == "ping":
            return self._ping_probe(target)
        return ProbeExecutionResult(
            target=target.target,
            probe_type=target.type,
            success=False,
            required=target.required,
            detail="unsupported probe type",
        )

    def _http_probe(self, target: ProbeTarget) -> ProbeExecutionResult:
        start = time.perf_counter()
        try:
            response = requests.get(target.target, timeout=target.timeout_seconds)
            latency_ms = int((time.perf_counter() - start) * 1000)
            ok = 200 <= response.status_code < 400
            return ProbeExecutionResult(
                target=target.target,
                probe_type="http",
                success=ok,
                required=target.required,
                latency_ms=latency_ms,
                detail=f"status={response.status_code}",
            )
        except Exception as exc:
            return ProbeExecutionResult(
                target=target.target,
                probe_type="http",
                success=False,
                required=target.required,
                detail=str(exc),
            )

    def _tcp_probe(self, target: ProbeTarget) -> ProbeExecutionResult:
        parsed = urlparse(target.target if "://" in target.target else f"tcp://{target.target}")
        host = parsed.hostname
        port = parsed.port
        start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=target.timeout_seconds):
                latency_ms = int((time.perf_counter() - start) * 1000)
                return ProbeExecutionResult(
                    target=target.target,
                    probe_type="tcp",
                    success=True,
                    required=target.required,
                    latency_ms=latency_ms,
                    detail="connected",
                )
        except Exception as exc:
            return ProbeExecutionResult(
                target=target.target,
                probe_type="tcp",
                success=False,
                required=target.required,
                detail=str(exc),
            )

    def _ping_probe(self, target: ProbeTarget) -> ProbeExecutionResult:
        is_windows = platform.system().lower().startswith("win")
        command = ["ping", "-n" if is_windows else "-c", "1", target.target]
        start = time.perf_counter()
        completed = subprocess.run(command, capture_output=True, text=True, timeout=target.timeout_seconds + 1)
        latency_ms = int((time.perf_counter() - start) * 1000)
        return ProbeExecutionResult(
            target=target.target,
            probe_type="ping",
            success=completed.returncode == 0,
            required=target.required,
            latency_ms=latency_ms,
            detail=(completed.stdout or completed.stderr).strip()[:300],
        )
