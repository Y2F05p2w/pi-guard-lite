from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
from contextlib import closing
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.common.db import get_connection, init_db
from app.common.event_store import list_events
from app.common.schemas import RawInputEvent
from app.policy.pipeline import PipelineProcessor
from app.policy.repository import list_blocklist, list_policies


DEFAULT_PORTS = [2201, 2202, 2203, 2204, 2205, 2206, 2207, 2208, 2209, 2210, 2211, 2212]


def reset_runtime_tables() -> None:
    init_db()
    with get_connection() as conn:
        for table in (
            "event",
            "feature",
            "policy",
            "blocklist",
            "probe_result",
            "audit_log",
            "baseline_profile",
        ):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()


def start_targets(
    bind_host: str,
    report_host: str,
    ports: list[int],
    processor: PipelineProcessor,
    stop_event: threading.Event,
) -> list[socket.socket]:
    listeners: list[socket.socket] = []

    def accept_loop(listener: socket.socket, port: int) -> None:
        listener.settimeout(0.5)
        while not stop_event.is_set():
            try:
                conn, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with closing(conn):
                payload = {
                    "src_ip": addr[0],
                    "dst_ip": report_host,
                    "dst_port": port,
                    "protocol": "tcp",
                }
                raw = RawInputEvent(source="scan.demo", payload={"message": json.dumps(payload)})
                processor.process_raw_event(raw, apply_policy=True, run_probe=False)

    for port in ports:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind_host, port))
        listener.listen(5)
        listeners.append(listener)
        threading.Thread(target=accept_loop, args=(listener, port), daemon=True).start()
    return listeners


def run_scan(target_host: str, ports: list[int], source_ip: str | None = None) -> list[dict]:
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            if source_ip:
                sock.bind((source_ip, 0))
            started = time.perf_counter()
            sock.connect((target_host, port))
            latency_ms = int((time.perf_counter() - started) * 1000)
            results.append({"port": port, "success": True, "latency_ms": latency_ms})
        except Exception as exc:
            results.append({"port": port, "success": False, "detail": str(exc)})
        finally:
            sock.close()
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a local or remote TCP scan demo and let Pi-Guard Lite detect it")
    parser.add_argument("--target-host", default="127.0.0.1", help="host to scan in local mode")
    parser.add_argument("--bind-host", default=None, help="listener bind host, e.g. 0.0.0.0 for remote scans")
    parser.add_argument("--report-host", default=None, help="host/IP recorded as the destination asset")
    parser.add_argument("--source-ip", default="127.0.0.2", help="source ip for local self-scan mode")
    parser.add_argument("--listen-only", action="store_true", help="only listen for another host to scan this machine")
    parser.add_argument("--wait-seconds", type=int, default=30, help="how long to wait in listen-only mode")
    args = parser.parse_args()

    reset_runtime_tables()
    processor = PipelineProcessor()
    stop_event = threading.Event()
    bind_host = args.bind_host or args.target_host
    report_host = args.report_host or args.target_host
    listeners = start_targets(bind_host, report_host, DEFAULT_PORTS, processor, stop_event)
    time.sleep(1)
    if args.listen_only:
        scan_results = []
        time.sleep(args.wait_seconds)
    else:
        scan_results = run_scan(args.target_host, DEFAULT_PORTS, source_ip=args.source_ip)
        time.sleep(2)
    stop_event.set()
    for listener in listeners:
        listener.close()

    payload = {
        "mode": "listen-only" if args.listen_only else "self-scan",
        "scan_results": scan_results,
        "events": list_events(50),
        "policies": list_policies(50),
        "blocklist": list_blocklist(50),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
