from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CVEMatch:
    cve_id: str
    cpe: str
    cvss: float | None
    summary: str
    source: str
    state: str = "Potential CVE match"


class CVEProvider(ABC):
    @abstractmethod
    def lookup(self, cpe: str) -> list[CVEMatch]:
        raise NotImplementedError


class NullCVEProvider(CVEProvider):
    """Safe offline provider: produces no claims when intelligence is unavailable."""
    def lookup(self, cpe: str) -> list[CVEMatch]:
        return []


class MemoryCVEProvider(CVEProvider):
    def __init__(self, entries: dict[str, list[CVEMatch]] | None = None):
        self.entries = entries or {}

    def lookup(self, cpe: str) -> list[CVEMatch]:
        return list(self.entries.get(cpe, []))

