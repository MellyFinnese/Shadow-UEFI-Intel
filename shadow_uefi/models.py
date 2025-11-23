from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


@dataclass
class ModuleInfo:
    guid: str
    name: str
    size: int
    timestamp: float
    entry_point: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "guid": self.guid,
            "name": self.name,
            "size": self.size,
            "timestamp": self.timestamp,
            "entry_point": self.entry_point,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "ModuleInfo":
        return cls(
            guid=str(data["guid"]),
            name=str(data.get("name", "")),
            size=int(data["size"]),
            timestamp=float(data["timestamp"]),
            entry_point=str(data.get("entry_point", "")),
        )


@dataclass
class FirmwareInventory:
    image_path: Path
    source: str
    size: int
    modules: List[ModuleInfo] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "firmware": {
                "path": str(self.image_path),
                "source": self.source,
                "size": self.size,
                "module_count": len(self.modules),
            },
            "modules": [module.to_dict() for module in self.modules],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "FirmwareInventory":
        firmware = data.get("firmware", {})
        modules = [ModuleInfo.from_dict(mod) for mod in data.get("modules", [])]
        return cls(
            image_path=Path(firmware.get("path", "")),
            source=str(firmware.get("source", "unknown")),
            size=int(firmware.get("size", 0)),
            modules=modules,
        )


@dataclass
class ModuleDelta:
    guid: str
    name: str
    change_type: str
    details: Dict[str, object]

    def to_dict(self) -> Dict[str, object]:
        return {
            "guid": self.guid,
            "name": self.name,
            "change_type": self.change_type,
            "details": self.details,
        }


@dataclass
class BaselineComparison:
    new_modules: List[ModuleDelta] = field(default_factory=list)
    missing_modules: List[ModuleDelta] = field(default_factory=list)
    modified_modules: List[ModuleDelta] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "new_modules": [delta.to_dict() for delta in self.new_modules],
            "missing_modules": [delta.to_dict() for delta in self.missing_modules],
            "modified_modules": [delta.to_dict() for delta in self.modified_modules],
        }


@dataclass
class AICommentary:
    summary: str
    highlights: List[str]

    def to_dict(self) -> Dict[str, object]:
        return {"summary": self.summary, "highlights": self.highlights}
