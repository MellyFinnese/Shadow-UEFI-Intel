from __future__ import annotations

from pathlib import Path
from typing import Optional

from .models import FirmwareInventory


def ingest_firmware(image_path: str, source: Optional[str] = None) -> FirmwareInventory:
    path = Path(image_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Firmware image not found: {path}")

    source_label = source or infer_source(path)
    size = path.stat().st_size
    return FirmwareInventory(image_path=path, source=source_label, size=size)


def infer_source(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(('.bin', '.rom')):
        return "chip-read"
    if name.endswith(('.cap', '.upd')):
        return "vendor-update"
    if name.endswith(('.img', '.qcow2')):
        return "vm-image"
    return "unknown"
