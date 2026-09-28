# Security Policy

Nexhost HSA is for systems and networks where the operator has explicit authorization. Every scan requires an authorization confirmation and must fit the declared/configured scope.

Safe Mode is on by default. Scanner profiles are fixed and do not accept arbitrary flags. The adapter uses `subprocess.run` with an argument list and `shell=False`. The product does not implement credential theft, evasion, persistence, automatic exploitation, destructive testing, or malware behavior.

Logs and scanner error output redact common secret labels. Raw evidence may still contain environment-sensitive metadata; protect the data directory with operating-system permissions and review evidence before sharing it. Findings distinguish observations/potential risks from confirmed vulnerabilities.

Report security defects privately to the project owner. Do not include live credentials, tokens, or third-party scan data.

