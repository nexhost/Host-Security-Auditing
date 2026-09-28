# Installation

## Kali Linux / Ubuntu

Install Python 3.12+, `python3-venv`, and Nmap using your distribution package manager, then run:

```bash
chmod +x install.sh
./install.sh
source .venv/bin/activate
nexhost-hsa gui
```

The installer creates a project-local virtual environment and installs the package. It does not grant elevated privileges or change firewall settings. PostgreSQL can be used later by setting `database_url` in the JSON configuration and installing a suitable SQLAlchemy driver.

To remove only the local environment and generated build artifacts:

```bash
./uninstall.sh
```

User data is deliberately retained and its path is printed by the uninstaller.

