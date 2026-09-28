from __future__ import annotations

from dataclasses import dataclass

from app.parsers.nmap_xml import ParsedHost, ParsedPort


@dataclass(frozen=True, slots=True)
class RuleFinding:
    rule_id: str
    title: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    category: str = "Potential Risk"


PORT_RULES = {
    21: ("HSA-EXP-001", "FTP service exposed", "medium", "Prefer SFTP/FTPS and restrict network access."),
    23: ("HSA-EXP-002", "Telnet service exposed", "high", "Disable Telnet and use SSH."),
    22: ("HSA-EXP-003", "SSH service exposed", "low", "Restrict trusted sources and enforce key-based authentication."),
    3389: ("HSA-EXP-004", "RDP service exposed", "medium", "Restrict through VPN/jump host and enable MFA/NLA."),
    445: ("HSA-EXP-005", "SMB service exposed", "medium", "Restrict SMB to required segments and disable legacy protocols."),
    6379: ("HSA-EXP-006", "Redis service exposed", "high", "Bind privately, authenticate, and restrict by firewall."),
    27017: ("HSA-EXP-007", "MongoDB service exposed", "high", "Require authentication and restrict network exposure."),
    9200: ("HSA-EXP-008", "Elasticsearch service exposed", "high", "Require authentication/TLS and restrict network exposure."),
    3306: ("HSA-EXP-009", "MySQL service exposed", "high", "Restrict database access to application hosts and require TLS/authentication."),
    5432: ("HSA-EXP-010", "PostgreSQL service exposed", "high", "Restrict database access to application hosts and require TLS/authentication."),
    1433: ("HSA-EXP-011", "Microsoft SQL Server exposed", "high", "Restrict database access and enforce encrypted authenticated connections."),
    161: ("HSA-EXP-012", "SNMP service exposed", "medium", "Restrict management networks and use SNMPv3 where supported."),
    5900: ("HSA-EXP-013", "Remote desktop service exposed", "medium", "Restrict remote administration through a controlled management path."),
}


def assess_host(host: ParsedHost) -> list[RuleFinding]:
    results: list[RuleFinding] = []
    open_ports = {p.number: p for p in host.ports if p.state == "open"}
    for number, port in open_ports.items():
        if number in PORT_RULES:
            rule_id, title, severity, recommendation = PORT_RULES[number]
            results.append(RuleFinding(
                rule_id, title, severity,
                "An exposed service was observed. Exposure alone does not prove a vulnerability.",
                _evidence(port), recommendation,
            ))
    if 80 in open_ports and 443 not in open_ports:
        results.append(RuleFinding(
            "HSA-WEB-001", "HTTP observed without HTTPS", "medium",
            "Plain HTTP was observed and no HTTPS service was detected in this scan.",
            _evidence(open_ports[80]), "Provide HTTPS, redirect HTTP, and validate TLS configuration.",
        ))
    for port in open_ports.values():
        if port.service and (port.service.product or port.service.version):
            results.append(RuleFinding(
                "HSA-INFO-001", "Service banner information observed", "informational",
                "Service product or version metadata was exposed during authorized detection.",
                _evidence(port), "Minimize unnecessary banner detail and keep the service patched.", "Observation",
            ))
    return results


def _evidence(port: ParsedPort) -> str:
    service = port.service.name if port.service and port.service.name else "unknown"
    return f"{port.protocol}/{port.number} state={port.state} service={service}"
