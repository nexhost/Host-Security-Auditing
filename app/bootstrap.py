from __future__ import annotations

from pathlib import Path

from app.core.config import AppConfig
from app.core.logging import configure_logging
from app.database.database import Database
from app.services.audit import AuditService


def build_service(config_path: Path | None = None, verbose: bool = False) -> AuditService:
    config = AppConfig.load(config_path)
    configure_logging(config.data_dir / "logs", verbose)
    database = Database(config.effective_database_url)
    database.create_schema()
    return AuditService(config, database)

