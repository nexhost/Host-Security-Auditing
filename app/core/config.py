from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class AppConfig:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("NEXHOST_DATA_DIR", "~/.local/share/nexhost-hsa")).expanduser())
    database_url: str | None = None
    safe_mode: bool = True
    max_targets: int = 256
    scan_timeout_seconds: int = 300
    nmap_path: str = "nmap"
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)
    demo_mode: bool = False
    n8n_webhook_url: str | None = None
    wazuh_api_url: str | None = None
    misp_api_url: str | None = None

    @property
    def effective_database_url(self) -> str:
        return self.database_url or f"sqlite:///{(self.data_dir / 'nexhost.db').as_posix()}"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    def prepare(self) -> None:
        for name in ("logs", "evidence", "reports", "scans"):
            (self.data_dir / name).mkdir(parents=True, exist_ok=True)

    @classmethod
    def load(cls, path: Path | None = None) -> AppConfig:
        config_path = path or Path(os.getenv("NEXHOST_CONFIG", "~/.config/nexhost-hsa/config.json")).expanduser()
        raw: dict[str, Any] = {}
        if config_path.exists():
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        if "data_dir" in raw:
            raw["data_dir"] = Path(raw["data_dir"]).expanduser()
        cfg = cls(**raw)
        cfg.prepare()
        return cfg

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(self)
        payload["data_dir"] = str(self.data_dir)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
