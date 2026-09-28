from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.database.models import Report
from app.reports.html import render_html
from app.services.audit import AuditService


class ReportService:
    def __init__(self, audit: AuditService):
        self.audit = audit

    def generate(self, destination: Path, format_name: str, scan_id: int | None = None) -> Path:
        payload = {
            "summary": self.audit.summary(scan_id),
            "assets": self.audit.assets(scan_id),
            "findings": self.audit.findings(scan_id),
        }
        destination.parent.mkdir(parents=True, exist_ok=True)
        if format_name == "html":
            destination.write_text(render_html(payload), encoding="utf-8")
        elif format_name == "pdf":
            try:
                from weasyprint import HTML
            except ImportError as exc:
                raise RuntimeError("PDF reporting requires the 'reports' dependency extra") from exc
            HTML(string=render_html(payload)).write_pdf(destination)
        elif format_name == "json":
            destination.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        else:
            raise ValueError("Report format must be html, pdf, or json")
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        with self.audit.database.session() as session:
            session.add(Report(scan_id=scan_id, format=format_name, path=str(destination), sha256=digest))
        return destination
