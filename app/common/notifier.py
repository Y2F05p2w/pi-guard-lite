from __future__ import annotations

from typing import Any

import requests

from app.common.config import get_settings
from app.common.schemas import NotificationResult


class Notifier:
    def __init__(self) -> None:
        settings = get_settings()
        self.config = settings.get("notifier", {})
        self.enabled = bool(self.config.get("enabled", False))
        self.channel = str(self.config.get("channel", "webhook"))
        self.webhook_url = str(self.config.get("webhook_url", "") or "")
        self.timeout_seconds = int(self.config.get("timeout_seconds", 3))

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "channel": self.channel,
            "webhook_configured": bool(self.webhook_url),
            "timeout_seconds": self.timeout_seconds,
        }

    def send(
        self,
        title: str,
        message: str,
        payload: dict[str, Any] | None = None,
        force: bool = False,
    ) -> NotificationResult:
        if not self.enabled and not force:
            return NotificationResult(
                success=True,
                sent=False,
                channel=self.channel,
                detail="notifier disabled",
            )

        if self.channel != "webhook":
            return NotificationResult(
                success=False,
                sent=False,
                channel=self.channel,
                detail="unsupported channel",
            )

        if not self.webhook_url:
            return NotificationResult(
                success=False,
                sent=False,
                channel=self.channel,
                detail="webhook_url not configured",
            )

        body = {
            "title": title,
            "message": message,
            "payload": payload or {},
        }
        try:
            response = requests.post(
                self.webhook_url,
                json=body,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            return NotificationResult(
                success=True,
                sent=True,
                channel=self.channel,
                detail=f"status={response.status_code}",
            )
        except Exception as exc:
            return NotificationResult(
                success=False,
                sent=False,
                channel=self.channel,
                detail=str(exc),
            )
