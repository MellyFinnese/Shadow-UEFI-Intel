from __future__ import annotations

import hashlib
import math
import uuid
from pathlib import Path
from typing import Iterable

from .models import FirmwareInventory, ModuleInfo


CHUNK_SIZE = 4096
MAX_MODULES = 64


def parse_modules(inventory: FirmwareInventory) -> FirmwareInventory:
    path = Path(inventory.image_path)
    modules = list(_extract_modules(path))
    inventory.modules = modules
    return inventory


def _extract_modules(path: Path) -> Iterable[ModuleInfo]:
    data = path.read_bytes()
    module_count = min(MAX_MODULES, math.ceil(len(data) / CHUNK_SIZE)) or 1

    for index in range(module_count):
        start = index * CHUNK_SIZE
        chunk = data[start : start + CHUNK_SIZE]
        if not chunk:
            break

        guid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{path}-{index}"))
        name = f"module_{index:03d}"
        size = len(chunk)
        timestamp = path.stat().st_mtime
        entry_point = hashlib.sha1(chunk).hexdigest()[:16]
        yield ModuleInfo(
            guid=guid,
            name=name,
            size=size,
            timestamp=timestamp,
            entry_point=f"0x{entry_point}",
        )

    if not data:
        guid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{path}-empty"))
        yield ModuleInfo(
            guid=guid,
            name="empty-image",
            size=0,
            timestamp=path.stat().st_mtime,
            entry_point="0x0",
        )
