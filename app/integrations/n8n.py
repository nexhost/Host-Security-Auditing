from __future__ import annotations

from datetime import datetime, timezone

from app.integrations.base import EventSink

ALLOWED_EVENTS = {"scan.completed", "finding.created", "finding.resolved", "new_service.detected", "asset.changed", "risk.changed"}


class N8nWebhook(EventSink):
    def __init__(self, endpoint: str, timeout: float = 10):
        if not endpoint.startswith("https://"):
            raise ValueError("n8n endpoint must use HTTPS")
        self.endpoint, self.timeout = endpoint, timeout

    def send(self, event: str, payload: dict) -> None:
        if event not in ALLOWED_EVENTS: raise ValueError("Unsupported event type")
        import httpx
        response = httpx.post(self.endpoint, json={"schema_version": 1, "event": event, "timestamp": datetime.now(timezone.utc).isoformat(), "data": payload}, timeout=self.timeout)
        response.raise_for_status()

