from __future__ import annotations

import logging
from typing import Any, Callable

from app.collector.scan_listener import TcpScanListener, parse_port_spec
from app.policy.pipeline import PipelineProcessor


logger = logging.getLogger(__name__)


class ScanListenerService:
    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        listener_class: type[TcpScanListener] = TcpScanListener,
        processor_factory: Callable[[], PipelineProcessor] = PipelineProcessor,
    ) -> None:
        self.config = config or {}
        self.listener_class = listener_class
        self.processor_factory = processor_factory
        self.listener: TcpScanListener | None = None
        self.processor: PipelineProcessor | None = None
        self.last_error: str | None = None
        self.running = False

    def start(self) -> dict[str, Any]:
        enabled = bool(self.config.get("enabled", False))
        auto = bool(self.config.get("auto_start_with_web", True))
        if not enabled or not auto:
            return self.status()

        if self.running:
            return self.status()

        bind_host = str(self.config.get("bind_host", "0.0.0.0"))
        report_host = str(self.config.get("report_host", "127.0.0.1"))
        ports = parse_port_spec(str(self.config.get("ports", "2201-2212")))

        self.processor = self.processor_factory()
        self.listener = self.listener_class(
            bind_host=bind_host,
            report_host=report_host,
            ports=ports,
            on_event=lambda raw: self.processor.process_raw_event(raw, apply_policy=True, run_probe=False),
        )
        try:
            self.listener.start()
            self.running = True
            self.last_error = None
            logger.info(
                "scan listener started bind_host=%s report_host=%s ports=%s",
                bind_host,
                report_host,
                ports,
            )
        except Exception as exc:
            self.last_error = str(exc)
            self.running = False
            self.listener = None
            logger.warning("scan listener failed to start: %s", exc)
        return self.status()

    def stop(self) -> None:
        if self.listener is not None:
            try:
                self.listener.stop()
            except Exception as exc:
                logger.warning("scan listener stop failed: %s", exc)
            finally:
                self.listener = None
        self.running = False

    def status(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.config.get("enabled", False)),
            "auto_start_with_web": bool(self.config.get("auto_start_with_web", True)),
            "bind_host": str(self.config.get("bind_host", "0.0.0.0")),
            "report_host": str(self.config.get("report_host", "127.0.0.1")),
            "ports": parse_port_spec(str(self.config.get("ports", "2201-2212"))),
            "running": self.running,
            "last_error": self.last_error,
        }
