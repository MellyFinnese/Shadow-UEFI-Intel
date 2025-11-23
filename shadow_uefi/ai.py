from __future__ import annotations

from typing import List

from .models import AICommentary, BaselineComparison, FirmwareInventory


SUSPICIOUS_THRESHOLD = 1024 * 512  # 512 KB


def generate_ai_commentary(inventory: FirmwareInventory, comparison: BaselineComparison) -> AICommentary:
    highlights: List[str] = []

    large_modules = [module for module in inventory.modules if module.size > SUSPICIOUS_THRESHOLD]
    if large_modules:
        highlights.append(
            f"Found {len(large_modules)} unusually large modules (> {SUSPICIOUS_THRESHOLD} bytes): "
            + ", ".join(module.name for module in large_modules)
        )

    if comparison.new_modules:
        highlights.append(f"{len(comparison.new_modules)} modules are new relative to baseline.")
    if comparison.missing_modules:
        highlights.append(f"{len(comparison.missing_modules)} modules disappeared versus baseline.")
    if comparison.modified_modules:
        highlights.append(f"{len(comparison.modified_modules)} modules changed size or entry points.")

    if not highlights:
        highlights.append("Firmware layout matches the baseline; no obvious anomalies detected.")

    summary = (
        "AI triage reviewed module inventory and baseline diffs."
        " Focus on new, missing, or abnormally sized modules for manual review."
    )
    return AICommentary(summary=summary, highlights=highlights)
