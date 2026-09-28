from __future__ import annotations

from abc import ABC, abstractmethod


class EventSink(ABC):
    @abstractmethod
    def send(self, event: str, payload: dict) -> None:
        raise NotImplementedError


class MemoryEventSink(EventSink):
    def __init__(self): self.events: list[tuple[str, dict]] = []
    def send(self, event: str, payload: dict) -> None: self.events.append((event, payload))

