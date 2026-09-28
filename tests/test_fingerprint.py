from app.engine.fingerprint import HostSnapshot, fingerprint


def test_fingerprint_is_reproducible_and_order_independent():
    first = HostSnapshot("10.0.0.1", "Linux", "Vendor", ((443, "tcp", "https", "1"), (22, "tcp", "ssh", "9")))
    second = HostSnapshot("10.0.0.1", "Linux", "Vendor", tuple(reversed(first.services)))
    assert fingerprint(first)[0] == fingerprint(second)[0]

