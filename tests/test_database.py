from pathlib import Path

from app.core.config import AppConfig
from app.database.database import Database
from app.services.audit import AuditService


def test_import_persists_inventory_and_findings(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'test.db'}")
    database.create_schema()
    service = AuditService(AppConfig(data_dir=tmp_path), database)
    fixture = Path(__file__).parent / "fixtures" / "nmap_sample.xml"
    scan_id = service.import_xml(fixture)
    assert scan_id > 0
    assert service.summary() == {"assets": 1, "ports": 2, "services": 2, "findings": 4, "scans": 1}
