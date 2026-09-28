from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Change:
    kind: str
    value: str


def compare_services(
    previous: set[tuple[int, str, str | None]], current: set[tuple[int, str, str | None]]
) -> list[Change]:
    changes: list[Change] = []
    previous_ports = {(p, proto) for p, proto, _ in previous}
    current_ports = {(p, proto) for p, proto, _ in current}
    for port in sorted(current_ports - previous_ports):
        changes.append(Change("NEW PORT", f"{port[1]}/{port[0]}"))
    for port in sorted(previous_ports - current_ports):
        changes.append(Change("REMOVED PORT", f"{port[1]}/{port[0]}"))
    shared = previous_ports & current_ports
    for port_number, proto in sorted(shared):
        old = next(x[2] for x in previous if x[:2] == (port_number, proto))
        new = next(x[2] for x in current if x[:2] == (port_number, proto))
        if old != new:
            changes.append(Change("VERSION CHANGE", f"{proto}/{port_number}: {old or '?'} -> {new or '?'}"))
    return changes
