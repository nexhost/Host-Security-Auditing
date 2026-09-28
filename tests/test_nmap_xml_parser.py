from pathlib import Path

import pytest

from app.core.exceptions import ParseError
from app.parsers.nmap_xml import parse_nmap_xml


FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def test_parser_extracts_host_service_and_os():
    parsed = parse_nmap_xml(FIXTURE)
    host = parsed.hosts[0]
    assert host.address == "192.168.56.10"
    assert host.vendor == "VirtualBox"
    assert host.os_matches == ["Linux 5.x"]
    assert host.ports[0].service.product == "OpenSSH"
    assert host.ports[0].service.cpes == ["cpe:/a:openbsd:openssh:9.6"]


def test_corrupt_xml_is_handled():
    with pytest.raises(ParseError):
        parse_nmap_xml(b"<nmaprun><host>")


def test_dtd_and_entities_are_rejected():
    with pytest.raises(ParseError):
        parse_nmap_xml(b"<!DOCTYPE x [<!ENTITY y SYSTEM 'file:///etc/passwd'>]><nmaprun>&y;</nmaprun>")
