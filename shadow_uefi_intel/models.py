"""Data models for firmware inventory and comparisons."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import json


def _iso_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


@dataclass
class FirmwareModule:
    guid: str
    size: int
    type: str
    timestamp: Optional[str] = None
    entry_point: Optional[str] = None
    path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FirmwareInventory:
    image_path: str
    created_at: str = field(default_factory=_iso_now)
    modules: List[FirmwareModule] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "image_path": self.image_path,
            "created_at": self.created_at,
            "modules": [m.to_dict() for m in self.modules],
            "metadata": self.metadata,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, path: Path) -> "FirmwareInventory":
        data = json.loads(path.read_text())
        modules = [FirmwareModule(**m) for m in data.get("modules", [])]
        return cls(
            image_path=data.get("image_path", str(path)),
            created_at=data.get("created_at", _iso_now()),
            modules=modules,
            metadata=data.get("metadata", {}),
        )


@dataclass
class ModuleDelta:
    guid: str
    baseline: Optional[FirmwareModule]
    current: Optional[FirmwareModule]
    delta: Dict[str, Any]


@dataclass
class BaselineComparison:
    new_modules: List[FirmwareModule] = field(default_factory=list)
    missing_modules: List[FirmwareModule] = field(default_factory=list)
    changed_modules: List[ModuleDelta] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "new_modules": [m.to_dict() for m in self.new_modules],
            "missing_modules": [m.to_dict() for m in self.missing_modules],
            "changed_modules": [
                {
                    "guid": delta.guid,
                    "baseline": delta.baseline.to_dict() if delta.baseline else None,
                    "current": delta.current.to_dict() if delta.current else None,
                    "delta": delta.delta,
                }
                for delta in self.changed_modules
            ],
        }


@dataclass
class TriageInsight:
    summary: str
    highlights: List[str]
    risk_level: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
