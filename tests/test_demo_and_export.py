import json

from app.core.config import AppConfig
from app.database.database import Database
from app.reports.export import export_csv, export_json
from app.services.audit import AuditService
from app.services.demo import load_demo_data


def test_demo_exact_counts_and_exports(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'test.db'}")
    database.create_schema()
    service = AuditService(AppConfig(data_dir=tmp_path), database)
    expected = load_demo_data(database)
    assert expected == {"assets": 24, "services": 87, "ports": 143, "findings": 31, "potential_cves": 11}
    assert service.summary()["ports"] == 143
    json_path = export_json(service, tmp_path / "out.json")
    csv_path = export_csv(service, tmp_path / "out.csv")
    assert json.loads(json_path.read_text())["summary"]["assets"] == 24
    assert "severity,title" in csv_path.read_text()

