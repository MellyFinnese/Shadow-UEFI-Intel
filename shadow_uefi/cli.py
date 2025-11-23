from __future__ import annotations

import argparse
import json
from pathlib import Path

from .ai import generate_ai_commentary
from .baseline import compare_inventories
from .ingestion import ingest_firmware
from .models import FirmwareInventory
from .parser import parse_modules
from .report import build_reports, save_json_report, save_markdown_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Shadow-UEFI-Intel inspection toolkit")
    parser.add_argument("firmware", help="Path to firmware image to analyze")
    parser.add_argument(
        "--baseline",
        help="Path to JSON baseline exported from a previous run",
        default=None,
    )
    parser.add_argument(
        "--source",
        help="Label describing the source of the image (chip-read, vendor-update, vm-image)",
        default=None,
    )
    parser.add_argument("--output-json", help="Where to write structured JSON report", default=None)
    parser.add_argument(
        "--output-md",
        help="Where to write Markdown summary",
        default=None,
    )
    return parser.parse_args()


def load_baseline(path: str) -> FirmwareInventory:
    data = json.loads(Path(path).read_text())
    return FirmwareInventory.from_dict(data.get("inventory", data))


def main() -> None:
    args = parse_args()

    inventory = parse_modules(ingest_firmware(args.firmware, source=args.source))

    baseline_inventory: FirmwareInventory
    if args.baseline:
        baseline_inventory = load_baseline(args.baseline)
    else:
        baseline_inventory = FirmwareInventory(
            image_path=inventory.image_path,
            source="self-baseline",
            size=inventory.size,
            modules=list(inventory.modules),
        )

    comparison = compare_inventories(inventory, baseline_inventory)
    commentary = generate_ai_commentary(inventory, comparison)

    report = build_reports(inventory, comparison, commentary)

    if args.output_json:
        save_json_report(report, Path(args.output_json))
    if args.output_md:
        save_markdown_report(inventory, comparison, commentary, Path(args.output_md))

    if not args.output_json and not args.output_md:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
