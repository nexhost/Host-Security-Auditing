from __future__ import annotations


class WazuhAdapter:
    def __init__(self, endpoint: str, token: str, timeout: float = 10):
        if not endpoint.startswith("https://"): raise ValueError("Wazuh endpoint must use HTTPS")
        self.endpoint, self.token, self.timeout = endpoint.rstrip("/"), token, timeout

    def export_event(self, payload: dict) -> None:
        import httpx
        response = httpx.post(f"{self.endpoint}/events", json=payload, headers={"Authorization": f"Bearer {self.token}"}, timeout=self.timeout)
        response.raise_for_status()

