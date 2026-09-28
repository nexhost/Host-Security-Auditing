from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

SECRET_PATTERN = re.compile(
    r"(?i)(authorization|password|passwd|token|api[_-]?key|cookie)(\s*[:=]\s*)([^\s,;]+)"
)


def redact(value: object) -> str:
    return SECRET_PATTERN.sub(r"\1\2[REDACTED]", str(value))


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = ()
        return True


def configure_logging(log_dir: Path, verbose: bool = False) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.addFilter(RedactingFilter())
    root.addHandler(console)
    for logger_name, filename in {
        "app": "app.log", "scanner": "scanner.log", "security": "security.log", "audit": "audit.log"
    }.items():
        handler = RotatingFileHandler(log_dir / filename, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        handler.setFormatter(formatter)
        handler.addFilter(RedactingFilter())
        logging.getLogger(logger_name).addHandler(handler)

