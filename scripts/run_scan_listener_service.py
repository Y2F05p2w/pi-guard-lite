from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.collector.scan_listener import TcpScanListener, parse_port_spec
from app.common.db import init_db
from app.common.logger import setup_logging
from app.policy.pipeline import PipelineProcessor


def main() -> None:
    parser = argparse.ArgumentParser(description="Run persistent TCP scan listener for Pi-Guard Lite")
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--report-host", default="127.0.0.1")
    parser.add_argument("--ports", default="2201-2212")
    parser.add_argument("--no-policy", action="store_true")
    parser.add_argument("--no-probe", action="store_true")
    args = parser.parse_args()

    setup_logging()
    init_db()
    logger = logging.getLogger(__name__)
    processor = PipelineProcessor()

    def handle(raw_event):
        result = processor.process_raw_event(
            raw_event,
            apply_policy=not args.no_policy,
            run_probe=not args.no_probe,
        )
        logger.info(
            "scan-listener processed event_id=%s type=%s risk=%s src=%s dst_port=%s",
            result["event_id"],
            result["event"]["event_type"],
            result["risk"]["risk_score"],
            result["event"]["src_ip"],
            result["event"].get("dst_port"),
        )

    ports = parse_port_spec(args.ports)
    logger.info(
        "starting scan listener bind_host=%s report_host=%s ports=%s",
        args.bind_host,
        args.report_host,
        ports,
    )
    listener = TcpScanListener(
        bind_host=args.bind_host,
        report_host=args.report_host,
        ports=ports,
        on_event=handle,
    )
    try:
        listener.serve_forever()
    except KeyboardInterrupt:
        logger.info("scan listener interrupted by user")
    finally:
        listener.stop()
        logger.info("scan listener stopped")


if __name__ == "__main__":
    main()
