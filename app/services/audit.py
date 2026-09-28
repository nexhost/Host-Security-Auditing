from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func, select

from app.core.config import AppConfig
from app.core.logging import redact
from app.core.security import ScopeValidator
from app.database.database import Database
from app.database.models import AuditLog, Evidence, Finding, Port, Scan, Service
from app.database.repositories import InventoryRepository
from app.engine.security_checks import assess_host
from app.parsers.nmap_xml import ParsedScan, parse_nmap_xml
from app.scanners.base import ScannerAdapter
from app.scanners.nmap import NmapScanner


class AuditService:
    def __init__(self, config: AppConfig, database: Database, scanner: ScannerAdapter | None = None):
        self.config = config
        self.database = database
        self.validator = ScopeValidator(config.allowlist, config.denylist, config.max_targets)
        self.scanner = scanner or NmapScanner(config.data_dir / "scans", config.nmap_path, config.scan_timeout_seconds, config.safe_mode)

    def run_scan(self, target: str, scope: str | None, profile: str, authorized: bool) -> int:
        validated = self.validator.validate(target, scope, authorized)
        with self.database.session() as session:
            scan = Scan(target=validated.value, scope=scope, profile=profile, status="running", authorized=True)
            session.add(scan)
            session.flush()
            scan_id = scan.id
            session.add(AuditLog(action="scan.authorized", detail=f"target={target} scope={scope} profile={profile}"))
        try:
            execution = self.scanner.scan(validated.value, profile)
            parsed = parse_nmap_xml(execution.xml_path)
            evidence_path = self._preserve_evidence(execution.xml_path, scan_id)
            self._persist(
                scan_id, parsed, evidence_path, execution.exit_code,
                command_metadata=json.dumps({"executable": Path(execution.command[0]).name, "profile": profile,
                                             "argument_count": len(execution.command), "started_at": execution.started_at,
                                             "finished_at": execution.finished_at}),
                scanner_stdout=execution.stdout, scanner_stderr=execution.stderr,
            )
            from app.services.posture import PostureService
            PostureService(self.database).process_scan(scan_id)
            return scan_id
        except Exception as exc:
            with self.database.session() as session:
                failed_scan = session.get(Scan, scan_id)
                if failed_scan:
                    failed_scan.status = "failed"
                    failed_scan.finished_at = datetime.now(timezone.utc)
                    failed_scan.error = redact(exc)
                session.add(AuditLog(action="scan.failed", detail=f"scan_id={scan_id} error={redact(exc)}"))
            raise

    def import_xml(self, path: Path, target: str = "imported", profile: str = "standard") -> int:
        parsed = parse_nmap_xml(path)
        with self.database.session() as session:
            scan = Scan(target=target, profile=profile, status="running", authorized=True)
            session.add(scan)
            session.flush()
            scan_id = scan.id
        evidence_path = self._preserve_evidence(path, scan_id)
        self._persist(scan_id, parsed, evidence_path, 0, command_metadata=json.dumps({"source": "xml_import"}))
        from app.services.posture import PostureService
        PostureService(self.database).process_scan(scan_id)
        return scan_id

    def _preserve_evidence(self, source: Path, scan_id: int) -> Path:
        destination = self.config.evidence_dir / f"scan-{scan_id}.xml"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.resolve() != destination.resolve():
            shutil.copy2(source, destination)
        return destination

    def _persist(self, scan_id: int, parsed: ParsedScan, evidence_path: Path, exit_code: int,
                 command_metadata: str | None = None, scanner_stdout: str | None = None,
                 scanner_stderr: str | None = None) -> None:
        digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        with self.database.session() as session:
            scan = session.get(Scan, scan_id)
            assert scan is not None
            repo = InventoryRepository(session)
            for host in parsed.hosts:
                asset = repo.upsert_asset(
                    host.address, address_type=host.address_type, mac=host.mac, vendor=host.vendor,
                    hostname=host.hostnames[0] if host.hostnames else None, status=host.status,
                    os_name=host.os_matches[0] if host.os_matches else None,
                )
                for item in host.ports:
                    port = repo.add_port(asset, scan, port_number=item.number, protocol=item.protocol, state=item.state, reason=item.reason)
                    if item.service:
                        session.add(Service(
                            port_id=port.id, name=item.service.name, product=item.service.product,
                            version=item.service.version, extra_info=item.service.extra_info,
                            method=item.service.method, confidence=item.service.confidence,
                            cpe="\n".join(item.service.cpes) or None,
                        ))
                for finding in assess_host(host):
                    session.add(Finding(
                        asset_id=asset.id, scan_id=scan.id, rule_id=finding.rule_id, title=finding.title,
                        severity=finding.severity, description=finding.description, evidence=finding.evidence,
                        recommendation=finding.recommendation, category=finding.category,
                    ))
            scan.status = "completed"
            scan.exit_code = exit_code
            scan.xml_path = str(evidence_path)
            scan.finished_at = datetime.now(timezone.utc)
            scan.command_metadata = command_metadata
            scan.scanner_stdout = redact(scanner_stdout or "")
            scan.scanner_stderr = redact(scanner_stderr or "")
            session.add(Evidence(scan_id=scan.id, kind="nmap_xml", path=str(evidence_path), sha256=digest))
            session.add(AuditLog(action="scan.completed", detail=f"scan_id={scan.id} hosts={len(parsed.hosts)}"))

    def summary(self, scan_id: int | None = None) -> dict[str, int]:
        with self.database.session() as session:
            if scan_id is not None:
                return {
                    "assets": session.scalar(select(func.count(func.distinct(Port.asset_id))).where(Port.scan_id == scan_id)) or 0,
                    "ports": session.scalar(select(func.count(Port.id)).where(Port.scan_id == scan_id)) or 0,
                    "services": session.scalar(select(func.count(Service.id)).join(Port).where(Port.scan_id == scan_id)) or 0,
                    "findings": session.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan_id)) or 0,
                    "scans": session.scalar(select(func.count(Scan.id)).where(Scan.id == scan_id)) or 0,
                }
            return InventoryRepository(session).summary()

    def assets(self, scan_id: int | None = None) -> list[dict]:
        from app.database.models import Asset
        with self.database.session() as session:
            statement = select(Asset).order_by(Asset.address)
            if scan_id is not None:
                statement = statement.where(Asset.id.in_(select(Port.asset_id).where(Port.scan_id == scan_id)))
            rows = session.scalars(statement).all()
            return [{"id": x.id, "address": x.address, "hostname": x.hostname, "status": x.status, "os": x.os_name} for x in rows]

    def findings(self, scan_id: int | None = None) -> list[dict]:
        with self.database.session() as session:
            statement = select(Finding).order_by(Finding.id)
            if scan_id is not None:
                statement = statement.where(Finding.scan_id == scan_id)
            rows = session.scalars(statement).all()
            return [{"severity": x.severity, "title": x.title, "id": x.id, "asset_id": x.asset_id,
                     "rule_id": x.rule_id, "category": x.category, "status": x.status,
                     "evidence": x.evidence, "recommendation": x.recommendation} for x in rows]

    def scans(self) -> list[dict]:
        with self.database.session() as session:
            rows = session.scalars(select(Scan).order_by(Scan.id.desc())).all()
            return [{"id": x.id, "target": x.target, "profile": x.profile, "status": x.status,
                     "started_at": x.started_at, "finished_at": x.finished_at} for x in rows]

    def services(self, scan_id: int | None = None) -> list[dict]:
        from app.database.models import Asset
        with self.database.session() as session:
            statement = (
                select(Asset.address, Port.port_number, Port.protocol, Port.state, Service.name,
                       Service.product, Service.version, Service.cpe)
                .join(Port, Port.asset_id == Asset.id).outerjoin(Service, Service.port_id == Port.id)
                .order_by(Asset.address, Port.port_number)
            )
            if scan_id is not None:
                statement = statement.where(Port.scan_id == scan_id)
            rows = session.execute(statement).all()
            return [{"address": a, "port": p, "protocol": proto, "state": state, "service": name,
                     "product": product, "version": version, "cpe": cpe}
                    for a, p, proto, state, name, product, version, cpe in rows]

    def vulnerabilities(self) -> list[dict]:
        from app.database.models import Vulnerability
        with self.database.session() as session:
            rows = session.scalars(select(Vulnerability).order_by(Vulnerability.id)).all()
            return [{"id": x.id, "asset_id": x.asset_id, "cve": x.cve_id, "cvss": x.cvss,
                     "state": x.state, "source": x.source} for x in rows]

    def compliance(self, scan_id: int | None = None) -> list[dict]:
        from app.database.models import ComplianceControl, ComplianceMapping
        with self.database.session() as session:
            statement = (
                select(ComplianceMapping, ComplianceControl)
                .join(ComplianceControl, ComplianceControl.id == ComplianceMapping.control_id)
                .order_by(ComplianceControl.framework, ComplianceControl.control_id)
            )
            if scan_id is not None:
                statement = statement.where(ComplianceMapping.scan_id == scan_id)
            rows = session.execute(statement).all()
            return [{"scan_id": m.scan_id, "framework": c.framework, "control": c.control_id,
                     "title": c.title, "status": m.status, "evidence": m.evidence,
                     "recommendation": m.recommendation} for m, c in rows]
