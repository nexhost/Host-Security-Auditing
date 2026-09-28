from app.intelligence.correlation import correlate
from app.intelligence.cve import CVEMatch, MemoryCVEProvider


def test_cve_matches_are_provider_backed_and_deduplicated():
    cpe = "cpe:/a:vendor:product:1.0"
    match = CVEMatch("CVE-2026-0001", cpe, 7.5, "Synthetic test entry", "test")
    results = correlate([cpe, cpe, "not-a-cpe"], MemoryCVEProvider({cpe: [match]}))
    assert results == [match]
    assert results[0].state == "Potential CVE match"

