from app.core.config import AppConfig
from app.database.database import Database
from app.reports.service import ReportService
from app.services.audit import AuditService
from app.services.demo import load_demo_data


def test_html_report_is_generated_and_registered(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    database.create_schema()
    audit = AuditService(AppConfig(data_dir=tmp_path), database)
    load_demo_data(database)
    output = ReportService(audit).generate(tmp_path / "report.html", "html", scan_id=1)
    text = output.read_text(encoding="utf-8")
    assert "Security Posture Report" in text
    assert "does not assert legal compliance" in text
