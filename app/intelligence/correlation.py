from __future__ import annotations

from app.intelligence.cpe import normalize_cpe
from app.intelligence.cve import CVEMatch, CVEProvider


def correlate(cpes: list[str], provider: CVEProvider) -> list[CVEMatch]:
    matches: dict[str, CVEMatch] = {}
    for raw in cpes:
        cpe = normalize_cpe(raw)
        if not cpe:
            continue
        for match in provider.lookup(cpe):
            matches[match.cve_id] = match
    return sorted(matches.values(), key=lambda item: item.cve_id)

