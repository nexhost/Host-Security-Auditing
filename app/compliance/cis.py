from app.compliance.base import ControlDefinition

CONTROLS = (
    ControlDefinition("CIS Controls v8", "4.1", "Secure configuration process", "Establish and maintain secure configuration processes.", ("HSA-WEB-001", "HSA-EXP-002")),
    ControlDefinition("CIS Controls v8", "12.2", "Secure network infrastructure", "Establish and maintain a secure network architecture.", ("HSA-EXP-004", "HSA-EXP-005", "HSA-EXP-006")),
)

