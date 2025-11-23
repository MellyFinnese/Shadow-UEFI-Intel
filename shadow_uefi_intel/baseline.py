"""Baseline comparison utilities."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Tuple

from .models import BaselineComparison, FirmwareInventory, FirmwareModule, ModuleDelta


class BaselineComparator:
    def __init__(self, current: FirmwareInventory, baseline: FirmwareInventory):
        self.current = current
        self.baseline = baseline

    def compare(self) -> BaselineComparison:
        baseline_map = {mod.guid: mod for mod in self.baseline.modules}
        current_map = {mod.guid: mod for mod in self.current.modules}

        new_modules = [mod for guid, mod in current_map.items() if guid not in baseline_map]
        missing_modules = [mod for guid, mod in baseline_map.items() if guid not in current_map]

        changed_modules = []
        for guid, baseline_mod in baseline_map.items():
            current_mod = current_map.get(guid)
            if not current_mod:
                continue
            delta = self._diff_modules(baseline_mod, current_mod)
            if delta:
                changed_modules.append(
                    ModuleDelta(
                        guid=guid,
                        baseline=baseline_mod,
                        current=current_mod,
                        delta=delta,
                    )
                )

        return BaselineComparison(
            new_modules=new_modules,
            missing_modules=missing_modules,
            changed_modules=changed_modules,
        )

    def _diff_modules(self, baseline: FirmwareModule, current: FirmwareModule) -> Dict[str, Tuple[object, object]]:
        delta: Dict[str, Tuple[object, object]] = {}
        for field in ("size", "timestamp", "entry_point", "type"):
            if getattr(baseline, field) != getattr(current, field):
                delta[field] = (getattr(baseline, field), getattr(current, field))
        return delta


def load_baseline(path: Path) -> FirmwareInventory:
    return FirmwareInventory.from_json(path)
