# Nexhost HSA

Repository: https://github.com/nexhost/Host-Security-Auditing

Nexhost HSA is a local-first host security auditor and asset inventory for **authorized environments only**. It provides a PySide6 SOC interface, shared CLI/application services, scope enforcement, cancellable safe Nmap execution, XML evidence parsing, SQLite persistence, security observations, fingerprints, historical comparison, HSA risk, compliance mappings, provider-neutral CVE correlation, reports, opt-in SOC adapters, and deterministic demo data.

## Quick start

Requires Python 3.12+, Nmap, and Linux (Kali/Ubuntu supported).

```bash
git clone https://github.com/nexhost/Host-Security-Auditing.git
cd Host-Security-Auditing
./install.sh
source .venv/bin/activate
nexhost-hsa demo
nexhost-hsa summary
nexhost-hsa gui
```

Authorized CLI scan:

```bash
nexhost-hsa scan 192.168.56.10 --scope 192.168.56.0/24 --profile quick --authorized
```

The authorization flag is mandatory. Safe Mode uses fixed scan profiles, argument-list subprocess execution, conservative timing, and excludes evasion, brute force, exploitation, and destructive scripts.

Additional workflows:

```bash
nexhost-hsa services
nexhost-hsa vulnerabilities
nexhost-hsa compliance --scan 1
nexhost-hsa compare 1 2
nexhost-hsa report --scan 2 --format html --output report.html
nexhost-hsa export csv findings.csv --dataset findings
```

External CVE and SOC services are not required. The default CVE provider is offline and deliberately makes no vulnerability claims. Wazuh, n8n and MISP adapters are opt-in; MISP submission requires explicit confirmation for every indicator.

## Data

Default data lives under `~/.local/share/nexhost-hsa`. Set `NEXHOST_DATA_DIR` to override it and `NEXHOST_CONFIG` for a JSON config file. See [INSTALL.md](INSTALL.md), [SECURITY.md](SECURITY.md), and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

```bash
python -m pytest
python -m ruff check .
python -m mypy app
python -m app.cli.commands --help
```

No unit test performs a real network scan.
