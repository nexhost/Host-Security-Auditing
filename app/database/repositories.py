from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.models import Asset, Finding, Port, Scan, Service


class InventoryRepository:
    def __init__(self, session: Session):
        self.session = session

    def upsert_asset(self, address: str, **values) -> Asset:
        asset = self.session.scalar(select(Asset).where(Asset.address == address))
        if asset is None:
            asset = Asset(address=address, **values)
            self.session.add(asset)
        else:
            for key, value in values.items():
                if value is not None:
                    setattr(asset, key, value)
            asset.last_seen = datetime.now(timezone.utc)
        self.session.flush()
        return asset

    def add_port(self, asset: Asset, scan: Scan, **values) -> Port:
        port = Port(asset_id=asset.id, scan_id=scan.id, **values)
        self.session.add(port)
        self.session.flush()
        return port

    def summary(self) -> dict[str, int]:
        return {
            "assets": self.session.scalar(select(func.count(Asset.id))) or 0,
            "ports": self.session.scalar(select(func.count(Port.id))) or 0,
            "services": self.session.scalar(select(func.count(Service.id))) or 0,
            "findings": self.session.scalar(select(func.count(Finding.id))) or 0,
            "scans": self.session.scalar(select(func.count(Scan.id))) or 0,
        }

