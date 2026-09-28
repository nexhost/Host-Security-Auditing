from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RiskFactors:
    asset_criticality: float = 0.5
    exposure: float = 0.5
    severity: float = 0.5
    confidence: float = 0.5
    vulnerability_score: float = 0.0
    service_sensitivity: float = 0.5


def hsa_score(factors: RiskFactors) -> float:
    values = [
        factors.asset_criticality, factors.exposure, factors.severity,
        factors.confidence, factors.vulnerability_score, factors.service_sensitivity,
    ]
    if any(value < 0 or value > 1 for value in values):
        raise ValueError("Risk factors must be between 0 and 1")
    weights = (0.20, 0.20, 0.25, 0.10, 0.15, 0.10)
    return round(sum(value * weight for value, weight in zip(values, weights, strict=True)) * 100, 1)


def risk_level(score: float) -> str:
    if score >= 85: return "Critical"
    if score >= 65: return "High"
    if score >= 40: return "Medium"
    if score >= 15: return "Low"
    return "Informational"

