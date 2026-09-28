from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.database.models import Base


class Database:
    def __init__(self, url: str):
        self.engine: Engine = create_engine(url, future=True)
        if url.startswith("sqlite"):
            event.listen(self.engine, "connect", self._enable_foreign_keys)
        self.session_factory = sessionmaker(self.engine, expire_on_commit=False)

    @staticmethod
    def _enable_foreign_keys(connection, _record) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)
        self._apply_compatible_migrations()

    def _apply_compatible_migrations(self) -> None:
        """Small additive migrations for MVP databases; PostgreSQL-ready schema stays portable."""
        inspector = inspect(self.engine)
        if "scans" not in inspector.get_table_names():
            return
        existing = {column["name"] for column in inspector.get_columns("scans")}
        additions = {
            "command_metadata": "TEXT", "scanner_stdout": "TEXT", "scanner_stderr": "TEXT",
        }
        with self.engine.begin() as connection:
            for name, data_type in additions.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE scans ADD COLUMN {name} {data_type}"))

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
