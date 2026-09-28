from __future__ import annotations

from app.database.database import Database
from app.database.models import Asset, AuditLog, Finding, Port, Scan, Service


def load_demo_data(database: Database) -> dict[str, int]:
    """Create a repeatable 24-asset SOC demo with exact documented totals."""
    with database.session() as session:
        if session.query(Asset).filter(Asset.address.like("192.168.56.%")).count() >= 24:
            return {"assets": 24, "services": 87, "ports": 143, "findings": 31, "potential_cves": 11}
        scan = Scan(target="192.168.56.0/24", scope="192.168.56.0/24", profile="demo", status="completed", authorized=True)
        session.add(scan)
        session.flush()
        assets = []
        ports = []
        for index in range(1, 25):
            asset = Asset(address=f"192.168.56.{index + 9}", hostname=f"demo-host-{index:02d}", status="up", os_name="Demo Linux")
            session.add(asset)
            assets.append(asset)
        session.flush()
        for index in range(143):
            asset = assets[index % 24]
            # Each asset can receive several rows; keep the port tuple unique per scan.
            number = [22, 80, 443, 445, 3306, 8080][index % 6] + (index // 24) * 100
            port = Port(asset_id=asset.id, scan_id=scan.id, port_number=number, protocol="tcp", state="open", reason="demo")
            session.add(port)
            ports.append(port)
        session.flush()
        for index, port in enumerate(ports[:87]):
            names = ["ssh", "http", "https", "microsoft-ds", "mysql", "http-proxy"]
            session.add(Service(port_id=port.id, name=names[index % len(names)], product="Demo Service", version=f"{1 + index % 4}.0", method="demo", confidence=10))
        for index in range(31):
            session.add(Finding(
                asset_id=assets[index % 24].id, scan_id=scan.id, rule_id=f"DEMO-{index + 1:03d}",
                title="Demo exposure requiring review", severity=["low", "medium", "high", "critical"][index % 4],
                category="Potential Vulnerability" if index < 11 else "Potential Risk",
                description="Synthetic finding for interface evaluation; not a real vulnerability claim.",
                evidence=f"Synthetic demo evidence #{index + 1}", recommendation="Validate and remediate in the authorized environment.",
                status="Needs Validation" if index < 11 else "Open",
            ))
        session.add(AuditLog(action="demo.loaded", detail="24 assets, 143 ports, 87 services, 31 findings, 11 potential CVEs"))
    return {"assets": 24, "services": 87, "ports": 143, "findings": 31, "potential_cves": 11}
