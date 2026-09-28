import pytest

from app.risk.engine import calculate_risk
from app.risk.scoring import RiskFactors, hsa_score


def test_risk_is_bounded_and_classified():
    score, level = calculate_risk(asset_criticality=1, exposure=1, severity=1, confidence=1, vulnerability_score=1, service_sensitivity=1)
    assert score == 100
    assert level == "Critical"


def test_risk_rejects_invalid_factor():
    with pytest.raises(ValueError):
        hsa_score(RiskFactors(exposure=1.1))

