from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

from app.core.exceptions import NexhostError


@dataclass(frozen=True, slots=True)
class TLSResult:
    hostname: str
    port: int
    protocol: str | None
    cipher: str | None
    subject: str | None
    issuer: str | None
    not_before: str | None
    not_after: str | None
    hostname_valid: bool
    issues: tuple[str, ...]


def analyze_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> TLSResult:
    """Opt-in, non-destructive TLS handshake for an already-authorized target."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as secure:
                cert = cast(dict[str, Any], secure.getpeercert() or {})
                cipher = secure.cipher()
                issues: list[str] = []
                expires = cast(str | None, cert.get("notAfter"))
                if expires:
                    expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires), timezone.utc)
                    if expiry < datetime.now(timezone.utc):
                        issues.append("Certificate expired")
                return TLSResult(
                    hostname, port, secure.version(), cipher[0] if cipher else None,
                    _name(cert.get("subject")), _name(cert.get("issuer")),
                    cast(str | None, cert.get("notBefore")),
                    expires, True, tuple(issues),
                )
    except (OSError, ssl.SSLError, ssl.CertificateError) as exc:
        raise NexhostError(f"TLS analysis failed: {exc}") from exc


def _name(value) -> str | None:
    if not value:
        return None
    return ", ".join(f"{key}={item}" for group in value for key, item in group)
