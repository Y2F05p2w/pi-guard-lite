from __future__ import annotations

import json
import socket
import threading
import time
from contextlib import closing
from typing import Callable

from app.common.schemas import RawInputEvent


DEFAULT_SCAN_PORTS = list(range(2201, 2213))


def parse_port_spec(raw: str | None) -> list[int]:
    if not raw:
        return DEFAULT_SCAN_PORTS.copy()
    ports: set[int] = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_raw, end_raw = chunk.split("-", 1)
            start = int(start_raw)
            end = int(end_raw)
            for value in range(min(start, end), max(start, end) + 1):
                ports.add(value)
        else:
            ports.add(int(chunk))
    return sorted(port for port in ports if 1 <= port <= 65535)


class TcpScanListener:
    def __init__(
        self,
        bind_host: str,
        report_host: str,
        ports: list[int],
        on_event: Callable[[RawInputEvent], None],
    ) -> None:
        self.bind_host = bind_host
        self.report_host = report_host
        self.ports = ports
        self.on_event = on_event
        self.stop_event = threading.Event()
        self.listeners: list[socket.socket] = []
        self.threads: list[threading.Thread] = []

    def start(self) -> None:
        for port in self.ports:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.bind_host, port))
            listener.listen(5)
            self.listeners.append(listener)
            thread = threading.Thread(target=self._accept_loop, args=(listener, port), daemon=True)
            thread.start()
            self.threads.append(thread)

    def stop(self) -> None:
        self.stop_event.set()
        for listener in self.listeners:
            try:
                listener.close()
            except OSError:
                pass
        self.listeners.clear()

    def serve_forever(self, sleep_seconds: float = 1.0) -> None:
        self.start()
        try:
            while not self.stop_event.is_set():
                time.sleep(sleep_seconds)
        finally:
            self.stop()

    def _accept_loop(self, listener: socket.socket, port: int) -> None:
        listener.settimeout(0.5)
        while not self.stop_event.is_set():
            try:
                conn, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with closing(conn):
                payload = {
                    "src_ip": addr[0],
                    "dst_ip": self.report_host,
                    "dst_port": port,
                    "protocol": "tcp",
                }
                raw = RawInputEvent(
                    source="scan.listener",
                    payload={"message": json.dumps(payload)},
                    raw_path=f"scan://{self.bind_host}:{port}",
                )
                self.on_event(raw)
