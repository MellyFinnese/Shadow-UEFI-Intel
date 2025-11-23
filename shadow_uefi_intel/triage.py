"""Heuristic AI-assisted triage comments."""
from __future__ import annotations

from typing import List

from .models import BaselineComparison, FirmwareInventory, TriageInsight


class TriageEngine:
    def __init__(self, inventory: FirmwareInventory, comparison: BaselineComparison | None = None):
        self.inventory = inventory
        self.comparison = comparison

    def summarize(self) -> TriageInsight:
        highlights: List[str] = []
        risk_score = 0

        if self.comparison:
            if self.comparison.new_modules:
                highlights.append(
                    f"{len(self.comparison.new_modules)} module(s) are newly introduced compared to the baseline."
                )
                risk_score += min(4, len(self.comparison.new_modules))
            if self.comparison.missing_modules:
                highlights.append(
                    f"{len(self.comparison.missing_modules)} baseline module(s) are missing in the current image."
                )
                risk_score += min(4, len(self.comparison.missing_modules))
            if self.comparison.changed_modules:
                highlights.append(
                    f"{len(self.comparison.changed_modules)} module(s) changed size or metadata."
                )
                risk_score += min(5, len(self.comparison.changed_modules))

        large_modules = [m for m in self.inventory.modules if m.size > 1_000_000]
        if large_modules:
            highlights.append(
                f"{len(large_modules)} large module(s) exceed 1MB and may include bundled payloads or drivers."
            )
            risk_score += 2

        risk_level = self._risk_level(risk_score)
        summary = self._build_summary(risk_level, highlights)
        return TriageInsight(summary=summary, highlights=highlights, risk_level=risk_level)

    def _risk_level(self, score: int) -> str:
        if score >= 8:
            return "high"
        if score >= 4:
            return "moderate"
        return "low"

    def _build_summary(self, risk: str, highlights: List[str]) -> str:
        if not highlights:
            return "No notable anomalies detected based on available metadata."
        highlights_str = "; ".join(highlights)
        return f"Overall {risk} risk: {highlights_str}."
