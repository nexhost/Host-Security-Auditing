from __future__ import annotations


class MISPAdapter:
    ALLOWED_TYPES = {"ip-src", "ip-dst", "domain", "url", "sha256", "md5"}

    def __init__(self, endpoint: str, api_key: str, timeout: float = 10):
        if not endpoint.startswith("https://"): raise ValueError("MISP endpoint must use HTTPS")
        self.endpoint, self.api_key, self.timeout = endpoint.rstrip("/"), api_key, timeout

    def submit_indicator(self, event_id: str, indicator_type: str, value: str, explicit_confirmation: bool = False) -> None:
        if not explicit_confirmation: raise PermissionError("Explicit confirmation is required for MISP submission")
        if indicator_type not in self.ALLOWED_TYPES: raise ValueError("Unsupported MISP indicator type")
        import httpx
        response = httpx.post(
            f"{self.endpoint}/attributes/add/{event_id}", json={"type": indicator_type, "value": value},
            headers={"Authorization": self.api_key, "Accept": "application/json"}, timeout=self.timeout,
        )
        response.raise_for_status()

