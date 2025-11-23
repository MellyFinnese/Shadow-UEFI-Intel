"""Shadow-UEFI-Intel inspection toolkit."""

from .ingestion import ingest_firmware
from .parser import parse_modules
from .baseline import compare_inventories
from .ai import generate_ai_commentary
from .report import build_reports

__all__ = [
    "ingest_firmware",
    "parse_modules",
    "compare_inventories",
    "generate_ai_commentary",
    "build_reports",
]
