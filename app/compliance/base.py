from __future__ import annotations

from dataclasses import dataclass

VALID_STATUSES = {"Pass", "Fail", "Partial", "Not Applicable", "Needs Review"}


@dataclass(frozen=True, slots=True)
class ControlDefinition:
    framework: str
    control_id: str
    title: str
    description: str
    rule_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ControlResult:
    control: ControlDefinition
    status: str
    evidence: str
    recommendation: str


def assess_controls(controls: tuple[ControlDefinition, ...], finding_rule_ids: set[str]) -> list[ControlResult]:
    results = []
    for control in controls:
        matched = sorted(finding_rule_ids.intersection(control.rule_ids))
        results.append(ControlResult(
            control,
            "Needs Review" if matched else "Pass",
            f"Related findings: {', '.join(matched)}" if matched else "No related findings observed in this scan.",
            "Review and remediate linked findings." if matched else "Continue monitoring and validate scope coverage.",
        ))
    return results

