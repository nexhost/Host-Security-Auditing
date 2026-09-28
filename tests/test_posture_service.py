from pathlib import Path

from sqlalchemy import func, select

from app.core.config import AppConfig
from app.database.database import Database
from app.database.models import ComplianceMapping, Fingerprint
from app.services.audit import AuditService


def test_import_builds_fingerprint_risk_and_compliance(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'db.sqlite'}"); database.create_schema()
    service = AuditService(AppConfig(data_dir=tmp_path), database)
    scan_id = service.import_xml(Path(__file__).parent / "fixtures" / "nmap_sample.xml")
    with database.session() as session:
        assert session.scalar(select(func.count(Fingerprint.id))) == 1
        assert session.scalar(select(func.count(ComplianceMapping.id))) == 6
    assert len(service.compliance(scan_id)) == 6

