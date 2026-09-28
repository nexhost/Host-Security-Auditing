from __future__ import annotations

import csv
import json
from pathlib import Path

from app.services.audit import AuditService


def export_json(service: AuditService, destination: Path) -> Path:
    payload = {"summary": service.summary(), "assets": service.assets(), "findings": service.findings()}
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return destination


def export_csv(service: AuditService, destination: Path, dataset: str = "findings") -> Path:
    if dataset not in {"assets", "findings"}:
        raise ValueError("CSV dataset must be assets or findings")
    rows = getattr(service, dataset)()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        if not rows:
            handle.write("")
        else:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    return destination

