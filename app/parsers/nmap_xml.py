from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from app.core.exceptions import ParseError


@dataclass(slots=True)
class ParsedService:
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    method: str | None = None
    confidence: int | None = None
    cpes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ParsedPort:
    number: int
    protocol: str
    state: str
    reason: str | None
    service: ParsedService | None
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedHost:
    address: str
    address_type: str
    status: str
    mac: str | None = None
    vendor: str | None = None
    hostnames: list[str] = field(default_factory=list)
    ports: list[ParsedPort] = field(default_factory=list)
    os_matches: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ParsedScan:
    scanner: str
    args: str
    started: str | None
    hosts: list[ParsedHost]


def parse_nmap_xml(source: Path | str | bytes) -> ParsedScan:
    try:
        if isinstance(source, Path):
            raw = source.read_bytes()
        elif isinstance(source, bytes) or str(source).lstrip().startswith("<"):
            raw = source if isinstance(source, bytes) else source.encode()
        else:
            raw = Path(str(source)).read_bytes()
        if len(raw) > 50_000_000:
            raise ParseError("Nmap XML exceeds the 50 MB safety limit")
        lowered = raw.lower()
        if b"<!doctype" in lowered or b"<!entity" in lowered:
            raise ParseError("DTD and entity declarations are not allowed")
        root = ET.fromstring(raw)  # noqa: S314 - DTD/entities rejected; bounded local Nmap evidence.
    except (ET.ParseError, OSError) as exc:
        raise ParseError(f"Invalid Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ParseError("Unexpected XML root; expected nmaprun")
    hosts: list[ParsedHost] = []
    for node in root.findall("host"):
        addresses = node.findall("address")
        primary = next((a for a in addresses if a.get("addrtype") in {"ipv4", "ipv6"}), None)
        if primary is None or not primary.get("addr"):
            continue
        mac_node = next((a for a in addresses if a.get("addrtype") == "mac"), None)
        status_node = node.find("status")
        host = ParsedHost(
            address=primary.get("addr", ""),
            address_type=primary.get("addrtype", "unknown"),
            status=status_node.get("state", "unknown") if status_node is not None else "unknown",
            mac=mac_node.get("addr") if mac_node is not None else None,
            vendor=mac_node.get("vendor") if mac_node is not None else None,
            hostnames=[h.get("name", "") for h in node.findall("./hostnames/hostname") if h.get("name")],
            os_matches=[m.get("name", "") for m in node.findall("./os/osmatch") if m.get("name")],
        )
        for port_node in node.findall("./ports/port"):
            state = port_node.find("state")
            service_node = port_node.find("service")
            service = None
            if service_node is not None:
                accuracy = service_node.get("conf")
                service = ParsedService(
                    name=service_node.get("name"), product=service_node.get("product"),
                    version=service_node.get("version"), extra_info=service_node.get("extrainfo"),
                    method=service_node.get("method"), confidence=int(accuracy) if accuracy and accuracy.isdigit() else None,
                    cpes=[c.text for c in service_node.findall("cpe") if c.text],
                )
            host.ports.append(ParsedPort(
                number=int(port_node.get("portid", "0")), protocol=port_node.get("protocol", "tcp"),
                state=state.get("state", "unknown") if state is not None else "unknown",
                reason=state.get("reason") if state is not None else None, service=service,
                scripts={s.get("id", "unknown"): s.get("output", "") for s in port_node.findall("script")},
            ))
        hosts.append(host)
    return ParsedScan(root.get("scanner", "nmap"), root.get("args", ""), root.get("startstr"), hosts)
