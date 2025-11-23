from __future__ import annotations

from typing import Dict

from .models import BaselineComparison, FirmwareInventory, ModuleDelta, ModuleInfo


def compare_inventories(current: FirmwareInventory, baseline: FirmwareInventory) -> BaselineComparison:
    baseline_map: Dict[str, ModuleInfo] = {module.guid: module for module in baseline.modules}
    current_map: Dict[str, ModuleInfo] = {module.guid: module for module in current.modules}

    comparison = BaselineComparison()

    for guid, module in current_map.items():
        if guid not in baseline_map:
            comparison.new_modules.append(
                ModuleDelta(
                    guid=guid,
                    name=module.name,
                    change_type="added",
                    details={"size": module.size, "entry_point": module.entry_point},
                )
            )
        else:
            changes = _module_changes(module, baseline_map[guid])
            if changes:
                comparison.modified_modules.append(
                    ModuleDelta(guid=guid, name=module.name, change_type="modified", details=changes)
                )

    for guid, module in baseline_map.items():
        if guid not in current_map:
            comparison.missing_modules.append(
                ModuleDelta(
                    guid=guid,
                    name=module.name,
                    change_type="missing",
                    details={"size": module.size, "entry_point": module.entry_point},
                )
            )

    return comparison


def _module_changes(current: ModuleInfo, baseline: ModuleInfo) -> Dict[str, object]:
    changes: Dict[str, object] = {}
    if current.size != baseline.size:
        changes["size"] = {"current": current.size, "baseline": baseline.size}
    if current.timestamp != baseline.timestamp:
        changes["timestamp"] = {"current": current.timestamp, "baseline": baseline.timestamp}
    if current.entry_point != baseline.entry_point:
        changes["entry_point"] = {"current": current.entry_point, "baseline": baseline.entry_point}
    return changes
