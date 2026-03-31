from __future__ import annotations

from typing import Any

from app.common.db import get_connection
from app.common.event_store import list_events
from app.common.runtime_checks import collect_runtime_report
from app.policy.repository import list_policies


def build_dashboard_summary(
    *,
    recent_event_limit: int = 10,
    recent_policy_limit: int = 10,
    scan_listener_status: dict[str, Any] | None = None,
    notifier_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    with get_connection() as conn:
        stats = {
            "events": _count(conn, "event"),
            "policies": _count(conn, "policy"),
            "blocked": _count(conn, "blocklist"),
        }
        risk_summary = {
            "critical": _count_where(conn, "event", "risk_level = 'critical'"),
            "high": _count_where(conn, "event", "risk_level = 'high'"),
            "medium": _count_where(conn, "event", "risk_level = 'medium'"),
            "low": _count_where(conn, "event", "risk_level = 'low'"),
        }

    runtime = collect_runtime_report()
    runtime_summary = {
        "hostname": runtime["host"]["hostname"],
        "python": runtime["host"]["python"],
        "disk_used_percent": runtime["resources"]["disk"]["used_percent"],
        "temperature_c": runtime["resources"]["temperature_c"],
        "services": runtime["systemd"]["services"],
    }

    return {
        "stats": stats,
        "risk_summary": risk_summary,
        "recent_events": list_events(limit=recent_event_limit),
        "recent_policies": list_policies(limit=recent_policy_limit),
        "scan_listener_status": scan_listener_status or {},
        "notifier_status": notifier_status or {},
        "runtime_summary": runtime_summary,
    }


def _count(conn, table: str) -> int:
    row = conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
    return int(row["count"]) if row else 0


def _count_where(conn, table: str, where_sql: str) -> int:
    row = conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {where_sql}").fetchone()
    return int(row["count"]) if row else 0
