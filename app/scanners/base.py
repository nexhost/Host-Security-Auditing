from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ScanExecution:
    target: str
    profile: str
    command: tuple[str, ...]
    xml_path: Path
    started_at: str
    finished_at: str
    exit_code: int
    stdout: str
    stderr: str


class ScannerAdapter(ABC):
    @abstractmethod
    def scan(self, target: str, profile: str) -> ScanExecution:
        raise NotImplementedError

    def cancel(self) -> bool:
        """Request cancellation. Adapters without active work return False."""
        return False
