from __future__ import annotations


def severity_for_cvss(score: float | None) -> str:
    if score is None: return "Unknown"
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score > 0: return "Low"
    return "None"

