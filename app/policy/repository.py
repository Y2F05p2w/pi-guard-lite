from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.common.db import get_connection


def create_policy(
    event_id: int | None,
    action: str,
    target: str,
    ttl_seconds: int,
    status: str = "pending",
) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO policy (event_id, action, target, ttl, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event_id, action, target, ttl_seconds, status),
        )
        conn.commit()
        return int(cursor.lastrowid)


def update_policy_status(policy_id: int, status: str) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE policy SET status = ? WHERE id = ?", (status, policy_id))
        conn.commit()


def get_policy(policy_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM policy WHERE id = ?", (policy_id,)).fetchone()
    return dict(row) if row else None


def list_policies(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, event_id, action, target, ttl, status, created_at
            FROM policy
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def add_blocklist_entry(target_ip: str, source_reason: str, expire_at: str, status: str = "active") -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO blocklist (target_ip, source_reason, expire_at, status)
            VALUES (?, ?, ?, ?)
            """,
            (target_ip, source_reason, expire_at, status),
        )
        conn.commit()
        return int(cursor.lastrowid)


def update_blocklist_status(block_id: int, status: str) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE blocklist SET status = ? WHERE id = ?", (status, block_id))
        conn.commit()


def release_blocklist_by_ip(target_ip: str, status: str = "released") -> None:
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE blocklist
            SET status = ?
            WHERE target_ip = ? AND status IN ('active', 'simulated')
            """,
            (status, target_ip),
        )
        conn.commit()


def list_blocklist(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, target_ip, source_reason, expire_at, status, created_at
            FROM blocklist
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_expired_blocks(now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or datetime.now(UTC)
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, target_ip, source_reason, expire_at, status
            FROM blocklist
            WHERE status IN ('active', 'simulated') AND expire_at IS NOT NULL AND expire_at <= ?
            ORDER BY id ASC
            """,
            (now.isoformat(),),
        ).fetchall()
    return [dict(row) for row in rows]


def insert_probe_result(
    policy_id: int | None,
    probe_target: str,
    result: str,
    latency_ms: int | None,
) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO probe_result (policy_id, probe_target, result, latency_ms)
            VALUES (?, ?, ?, ?)
            """,
            (policy_id, probe_target, result, latency_ms),
        )
        conn.commit()
        return int(cursor.lastrowid)


def list_probe_results(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, policy_id, probe_target, result, latency_ms, created_at
            FROM probe_result
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
