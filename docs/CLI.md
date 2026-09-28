# CLI

- `nexhost-hsa gui` opens the desktop interface.
- `nexhost-hsa scan TARGET --scope CIDR --profile quick --authorized` runs an authorized audit.
- `nexhost-hsa import-xml FILE` imports existing Nmap XML without network activity.
- `nexhost-hsa assets`, `findings`, and `summary` query inventory.
- `nexhost-hsa services`, `vulnerabilities`, and `compliance --scan ID` query posture data.
- `nexhost-hsa compare PREVIOUS CURRENT` reports port and version changes.
- `nexhost-hsa report --scan ID --format html --output FILE` generates HTML, JSON, or PDF.
- `nexhost-hsa demo` loads deterministic demo content.
- `nexhost-hsa export json FILE` exports all core datasets.
- `nexhost-hsa export csv FILE --dataset findings` exports one table.
