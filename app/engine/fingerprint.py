from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HostSnapshot:
    address: str
    os_name: str | None
    vendor: str | None
    services: tuple[tuple[int, str, str | None, str | None], ...]
    technologies: tuple[str, ...] = ()
    tls: tuple[str, ...] = ()


def canonical_fingerprint(snapshot: HostSnapshot) -> str:
    payload = {
        "address": snapshot.address,
        "os": snapshot.os_name or "",
        "vendor": snapshot.vendor or "",
        "services": sorted(snapshot.services),
        "technologies": sorted(snapshot.technologies),
        "tls": sorted(snapshot.tls),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def fingerprint(snapshot: HostSnapshot) -> tuple[str, str]:
    canonical = canonical_fingerprint(snapshot)
    return hashlib.sha256(canonical.encode()).hexdigest(), canonical

