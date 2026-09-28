from app.compliance.base import assess_controls
from app.compliance.nist import CONTROLS


def test_compliance_requires_review_when_related_finding_exists():
    results = assess_controls(CONTROLS, {"HSA-EXP-002"})
    assert results[0].status == "Needs Review"
    assert "HSA-EXP-002" in results[0].evidence


def test_compliance_does_not_claim_certification():
    assert all(result.status == "Pass" for result in assess_controls(CONTROLS, set()))

