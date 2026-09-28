from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select

from app.compliance.base import assess_controls
from app.compliance.cis import CONTROLS as CIS_CONTROLS
from app.compliance.iso27001 import CONTROLS as ISO_CONTROLS
from app.compliance.nist import CONTROLS as NIST_CONTROLS
from app.database.database import Database
from app.database.models import (
    Asset, ComplianceControl, ComplianceMapping, Finding, Fingerprint, Port, Service,
    Technology, Vulnerability,
)
from app.engine.fingerprint import HostSnapshot, fingerprint
from app.engine.history import Change, compare_services
from app.intelligence.correlation import correlate
from app.intelligence.cve import CVEProvider, NullCVEProvider
from app.risk.engine import calculate_risk

SEVERITY = {"informational": 0.05, "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}


class PostureService:
    def __init__(self, database: Database, cve_provider: CVEProvider | None = None):
        self.database = database
        self.cve_provider = cve_provider or NullCVEProvider()

    def process_scan(self, scan_id: int) -> None:
        with self.database.session() as session:
            asset_ids = list(session.scalars(select(Port.asset_id).where(Port.scan_id == scan_id).distinct()))
            for asset_id in asset_ids:
                asset = session.get(Asset, asset_id)
                if asset is None:
                    continue
                rows = session.execute(
                    select(Port, Service).outerjoin(Service, Service.port_id == Port.id)
                    .where(Port.scan_id == scan_id, Port.asset_id == asset_id)
                ).all()
                services = tuple((p.port_number, p.protocol, s.name if s else None, s.version if s else None) for p, s in rows)
                digest, canonical = fingerprint(HostSnapshot(asset.address, asset.os_name, asset.vendor, services))
                session.add(Fingerprint(asset_id=asset.id, scan_id=scan_id, digest=digest, canonical_data=canonical))
                for _, service in rows:
                    if service and (service.product or service.name):
                        session.add(Technology(
                            asset_id=asset.id, scan_id=scan_id, name=service.product or service.name or "unknown",
                            version=service.version, source="nmap-service", confidence=(service.confidence or 5) * 10,
                        ))
                cpes = [cpe for _, service in rows if service and service.cpe for cpe in service.cpe.splitlines()]
                for match in correlate(cpes, self.cve_provider):
                    session.add(Vulnerability(
                        asset_id=asset.id, scan_id=scan_id, cve_id=match.cve_id, cpe=match.cpe,
                        cvss=match.cvss, state=match.state, source=match.source, summary=match.summary,
                    ))
                findings = list(session.scalars(select(Finding).where(Finding.scan_id == scan_id, Finding.asset_id == asset.id)))
                max_severity = max((SEVERITY.get(item.severity.lower(), 0.1) for item in findings), default=0.0)
                score, _ = calculate_risk(
                    asset_criticality=0.5, exposure=min(len(services) / 20, 1), severity=max_severity,
                    confidence=0.7 if findings else 0.3, vulnerability_score=0.0,
                    service_sensitivity=0.6 if any(p in {22, 445, 3389, 3306, 6379} for p, *_ in services) else 0.3,
                )
                asset.risk_score = score
            self._persist_compliance(session, scan_id)

    def _persist_compliance(self, session, scan_id: int) -> None:
        rules = set(session.scalars(select(Finding.rule_id).where(Finding.scan_id == scan_id)))
        controls = NIST_CONTROLS + CIS_CONTROLS + ISO_CONTROLS
        for result in assess_controls(controls, rules):
            control = session.scalar(select(ComplianceControl).where(
                ComplianceControl.framework == result.control.framework,
                ComplianceControl.control_id == result.control.control_id,
            ))
            if control is None:
                control = ComplianceControl(
                    framework=result.control.framework, control_id=result.control.control_id,
                    title=result.control.title, description=result.control.description,
                )
                session.add(control); session.flush()
            session.add(ComplianceMapping(
                control_id=control.id, scan_id=scan_id, status=result.status,
                evidence=result.evidence, recommendation=result.recommendation,
            ))

    def compare_scans(self, previous_scan: int, current_scan: int) -> dict[str, list[Change]]:
        with self.database.session() as session:
            def snapshot(scan_id: int):
                result: dict[str, set[tuple[int, str, str | None]]] = defaultdict(set)
                rows = session.execute(
                    select(Asset.address, Port.port_number, Port.protocol, Service.version)
                    .join(Port, Port.asset_id == Asset.id).outerjoin(Service, Service.port_id == Port.id)
                    .where(Port.scan_id == scan_id)
                )
                for address, port, protocol, version in rows:
                    result[address].add((port, protocol, version))
                return result
            old, new = snapshot(previous_scan), snapshot(current_scan)
            output: dict[str, list[Change]] = {}
            for address in sorted(set(old) | set(new)):
                changes = compare_services(old.get(address, set()), new.get(address, set()))
                if address not in old: changes.insert(0, Change("NEW", address))
                elif address not in new: changes.insert(0, Change("REMOVED", address))
                if changes: output[address] = changes
            return output
