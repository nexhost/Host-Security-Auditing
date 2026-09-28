#!/usr/bin/env bash
set -euo pipefail

if [[ -d "${PWD}/.venv" && -f "${PWD}/pyproject.toml" ]]; then
  rm -rf -- "${PWD}/.venv"
fi
rm -rf -- "${PWD}/build" "${PWD}/dist" "${PWD}/nexhost_hsa.egg-info"
echo "Local environment removed. User data was retained at ${NEXHOST_DATA_DIR:-$HOME/.local/share/nexhost-hsa}."

