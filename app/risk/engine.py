from app.risk.scoring import RiskFactors, hsa_score, risk_level


def calculate_risk(**factors: float) -> tuple[float, str]:
    score = hsa_score(RiskFactors(**factors))
    return score, risk_level(score)

