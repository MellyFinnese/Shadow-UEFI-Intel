# Shadow-UEFI-Intel

UEFI / firmware inspection toolkit that parses images, baselines modules, and uses an AI layer to flag suspicious changes for human review. Defensive intel only.

## What it does
- Ingests firmware images from chip reads, vendor update packages, or lab VMs
- Extracts DXE / PEI modules with GUIDs, sizes, and metadata (using `uefi_firmware` when available)
- Builds a structured inventory for repeatable baselining
- Compares images against previous baselines to spot new, missing, or changed modules
- Produces AI-style commentary to highlight modules that deserve manual review
- Generates JSON and Markdown reports suitable for automation and ticketing

## Quick start
1. Optional: install the UEFI parsing helper to enable deep extraction
   ```bash
   pip install uefi_firmware
   ```
2. Run the analyzer against a firmware image
   ```bash
   python -m shadow_uefi_intel path/to/firmware.bin \
     --json my_report.json \
     --markdown my_report.md
   ```
3. To compare against a previous baseline JSON
   ```bash
   python -m shadow_uefi_intel path/to/firmware.bin \
     --baseline baseline_inventory.json \
     --json comparison.json \
     --markdown comparison.md
   ```

The JSON report captures the raw inventory, baseline deltas, and triage summary. The Markdown report is tailored for wikis, tickets, and incident timelines.

## Notes
- If `uefi_firmware` is not installed or cannot parse the image, the tool falls back to a single-module inventory derived from the binary hash so you can still baseline and compare builds.
- The tool is defensive-only and generates human-readable commentary; it does not attempt exploitation or payload execution.
