from app.engine.security_checks import assess_host
from app.parsers.nmap_xml import ParsedHost, ParsedPort, ParsedService


def test_open_port_is_potential_risk_not_confirmed_vulnerability():
    host = ParsedHost("10.0.0.1", "ipv4", "up", ports=[ParsedPort(23, "tcp", "open", None, ParsedService(name="telnet"))])
    finding = assess_host(host)[0]
    assert finding.severity == "high"
    assert finding.category == "Potential Risk"

