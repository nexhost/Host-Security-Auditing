from app.compliance.base import ControlDefinition

CONTROLS = (
    ControlDefinition("ISO/IEC 27001:2022", "A.8.20", "Network security", "Networks and network devices should be secured, managed, and controlled.", ("HSA-EXP-001", "HSA-EXP-002", "HSA-EXP-004", "HSA-EXP-005")),
    ControlDefinition("ISO/IEC 27001:2022", "A.8.21", "Security of network services", "Security mechanisms and service levels should be identified and monitored.", ("HSA-WEB-001", "HSA-EXP-006", "HSA-EXP-007", "HSA-EXP-008")),
)

