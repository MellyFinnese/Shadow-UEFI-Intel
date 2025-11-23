"""Firmware ingestion and module parsing helpers."""
from __future__ import annotations

import hashlib
import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional
from datetime import datetime

from .models import FirmwareInventory, FirmwareModule


@dataclass
class ParsedFirmware:
    inventory: FirmwareInventory
    raw_bytes: bytes


class FirmwareParser:
    """Parse firmware images into a structured inventory."""

    def __init__(self, image_path: Path) -> None:
        self.image_path = Path(image_path)

    def parse(self) -> ParsedFirmware:
        raw_bytes = self.image_path.read_bytes()
        inventory = (
            self._parse_with_uefi_firmware(raw_bytes)
            or self._naive_fallback(raw_bytes)
        )
        inventory.metadata.update(
            {
                "byte_length": len(raw_bytes),
                "source": str(self.image_path),
            }
        )
        return ParsedFirmware(inventory=inventory, raw_bytes=raw_bytes)

    def _parse_with_uefi_firmware(self, raw_bytes: bytes) -> Optional[FirmwareInventory]:
        if importlib.util.find_spec("uefi_firmware") is None:
            return None

        from uefi_firmware import auto_parse

        firmware = auto_parse(raw_bytes)
        if firmware is None:
            return None

        firmware.parse()
        modules: List[FirmwareModule] = []
        for obj in self._iter_objects(firmware):
            guid = getattr(obj, "guid", None)
            size = getattr(obj, "size", None)
            obj_type = getattr(obj, "type", obj.__class__.__name__)
            if guid is None or size is None:
                continue
            entry_point = getattr(obj, "entry_point", None)
            timestamp = getattr(obj, "timestamp", None)
            path = "/".join(getattr(obj, "path", [])) if hasattr(obj, "path") else None
            modules.append(
                FirmwareModule(
                    guid=str(guid),
                    size=int(size),
                    type=str(obj_type),
                    timestamp=str(timestamp) if timestamp else None,
                    entry_point=str(entry_point) if entry_point else None,
                    path=path,
                )
            )

        if not modules:
            return None

        return FirmwareInventory(image_path=str(self.image_path), modules=modules)

    def _iter_objects(self, obj: object) -> Iterable[object]:
        yield obj
        for child in getattr(obj, "objects", []) or []:
            yield from self._iter_objects(child)
        for section in getattr(obj, "sections", []) or []:
            yield from self._iter_objects(section)

    def _naive_fallback(self, raw_bytes: bytes) -> FirmwareInventory:
        digest = hashlib.sha256(raw_bytes).hexdigest()
        pseudo_guid = f"pseudo-{digest[:32]}"
        mtime = datetime.utcfromtimestamp(self.image_path.stat().st_mtime)
        module = FirmwareModule(
            guid=pseudo_guid,
            size=len(raw_bytes),
            type="firmware-image",
            timestamp=mtime.replace(microsecond=0).isoformat() + "Z",
            entry_point=None,
            path=str(self.image_path.name),
        )
        return FirmwareInventory(image_path=str(self.image_path), modules=[module])
