from app.compliance.base import ControlDefinition

CONTROLS = (
    ControlDefinition("NIST CSF 2.0", "ID.AM-03", "Network communication representations", "Maintain representations of authorized network communication and flows.", ("HSA-EXP-001", "HSA-EXP-002", "HSA-EXP-004", "HSA-EXP-005")),
    ControlDefinition("NIST CSF 2.0", "PR.PS-01", "Configuration management", "Configuration management practices are established and applied.", ("HSA-WEB-001", "HSA-EXP-006", "HSA-EXP-007", "HSA-EXP-008")),
)

