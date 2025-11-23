"""Report writers for JSON and Markdown outputs."""
from __future__ import annotations

from pathlib import Path
from typing import List

from .models import BaselineComparison, FirmwareInventory, TriageInsight


class ReportBuilder:
    def __init__(self, inventory: FirmwareInventory):
        self.inventory = inventory

    def write_json(self, path: Path, comparison: BaselineComparison | None, triage: TriageInsight | None) -> None:
        payload = {
            "inventory": self.inventory.to_dict(),
            "comparison": comparison.to_dict() if comparison else None,
            "triage": triage.to_dict() if triage else None,
        }
        path.write_text(self.inventory.to_json(indent=2) if comparison is None and triage is None else _json_dumps(payload))

    def write_markdown(self, path: Path, comparison: BaselineComparison | None, triage: TriageInsight | None) -> None:
        lines: List[str] = []
        lines.append(f"# Firmware Report for {self.inventory.image_path}\n")
        lines.append(f"Generated: {self.inventory.created_at}\n")
        lines.append("## Module Inventory")
        for mod in self.inventory.modules:
            lines.append(f"- `{mod.guid}` ({mod.type}, {mod.size} bytes)")
            if mod.timestamp:
                lines.append(f"  - Timestamp: {mod.timestamp}")
            if mod.entry_point:
                lines.append(f"  - Entry: {mod.entry_point}")
            if mod.path:
                lines.append(f"  - Path: {mod.path}")
        lines.append("")

        if comparison:
            lines.append("## Baseline Comparison")
            lines.append(f"- New modules: {len(comparison.new_modules)}")
            lines.append(f"- Missing modules: {len(comparison.missing_modules)}")
            lines.append(f"- Changed modules: {len(comparison.changed_modules)}\n")
            if comparison.new_modules:
                lines.append("### New Modules")
                lines.extend(self._list_modules(comparison.new_modules))
            if comparison.missing_modules:
                lines.append("### Missing Modules")
                lines.extend(self._list_modules(comparison.missing_modules))
            if comparison.changed_modules:
                lines.append("### Changed Modules")
                for delta in comparison.changed_modules:
                    lines.append(f"- `{delta.guid}`")
                    for field, (before, after) in delta.delta.items():
                        lines.append(f"  - {field}: {before} -> {after}")
            lines.append("")

        if triage:
            lines.append("## AI-Assisted Triage")
            lines.append(f"- Risk level: **{triage.risk_level}**")
            lines.append(f"- Summary: {triage.summary}")
            if triage.highlights:
                lines.append("- Highlights:")
                for item in triage.highlights:
                    lines.append(f"  - {item}")

        path.write_text("\n".join(lines))

    def _list_modules(self, modules) -> List[str]:
        lines: List[str] = []
        for mod in modules:
            lines.append(f"- `{mod.guid}` ({mod.type}, {mod.size} bytes)")
            if mod.timestamp:
                lines.append(f"  - Timestamp: {mod.timestamp}")
            if mod.path:
                lines.append(f"  - Path: {mod.path}")
        lines.append("")
        return lines


def _json_dumps(payload) -> str:
    import json

    return json.dumps(payload, indent=2)
