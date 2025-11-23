from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from .models import AICommentary, BaselineComparison, FirmwareInventory


def build_reports(
    inventory: FirmwareInventory,
    comparison: BaselineComparison,
    commentary: AICommentary,
) -> Dict[str, object]:
    return {
        "inventory": inventory.to_dict(),
        "baseline_comparison": comparison.to_dict(),
        "ai_commentary": commentary.to_dict(),
    }


def save_json_report(report: Dict[str, object], output_path: Path) -> None:
    output_path = output_path.expanduser()
    output_path.write_text(json.dumps(report, indent=2))


def save_markdown_report(
    inventory: FirmwareInventory,
    comparison: BaselineComparison,
    commentary: AICommentary,
    output_path: Path,
) -> None:
    lines = [
        "# Shadow-UEFI-Intel Firmware Report",
        "",
        f"**Image:** {inventory.image_path}",
        f"**Source:** {inventory.source}",
        f"**Size:** {inventory.size} bytes",
        "",
        "## Module Inventory",
    ]

    for module in inventory.modules:
        lines.append(f"- `{module.name}` ({module.guid}) — {module.size} bytes, entry {module.entry_point}")

    lines.append("\n## Baseline Comparison")
    if comparison.new_modules:
        lines.append("### New Modules")
        for delta in comparison.new_modules:
            lines.append(f"- `{delta.name}` ({delta.guid}) — size {delta.details.get('size')}")
    if comparison.missing_modules:
        lines.append("### Missing Modules")
        for delta in comparison.missing_modules:
            lines.append(f"- `{delta.name}` ({delta.guid})")
    if comparison.modified_modules:
        lines.append("### Modified Modules")
        for delta in comparison.modified_modules:
            size_change = delta.details.get("size")
            entry_change = delta.details.get("entry_point")
            pieces = []
            if size_change:
                pieces.append(f"size {size_change['baseline']} -> {size_change['current']}")
            if entry_change:
                pieces.append(
                    f"entry {entry_change['baseline']} -> {entry_change['current']}"
                )
            lines.append(f"- `{delta.name}` ({delta.guid}) — " + "; ".join(pieces))

    if not any([comparison.new_modules, comparison.missing_modules, comparison.modified_modules]):
        lines.append("No differences detected relative to the baseline.")

    lines.append("\n## AI Commentary")
    lines.append(commentary.summary)
    for highlight in commentary.highlights:
        lines.append(f"- {highlight}")

    output_path = output_path.expanduser()
    output_path.write_text("\n".join(lines))
