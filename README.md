# Shadow-UEFI-Intel

UEFI / firmware inspection toolkit that parses images, baselines modules, and uses an AI layer to flag suspicious changes for human review. Defensive intel only.

## Features

- **Firmware image ingestion**: accepts chip reads, vendor update packages, and VM/lab images with automatic source inference.
- **Module parsing & metadata**: slices firmware into deterministic pseudo-modules, capturing GUIDs, sizes, timestamps, and entry-point fingerprints for inventorying.
- **Baseline comparison**: compares current inventory to a baseline snapshot to detect new, missing, or modified modules.
- **AI-assisted triage**: surfaces highlight strings that call out new/missing modules and unusually large modules for manual review.
- **Reports for workflows**: emits structured JSON for pipelines and Markdown for tickets or analyst notes.

## Quickstart

1. Analyze a firmware image and print JSON to stdout:
   ```bash
   python -m shadow_uefi README.md
   ```

2. Save reports to disk:
   ```bash
   python -m shadow_uefi firmware.bin --output-json report.json --output-md report.md
   ```

3. Compare against a saved baseline JSON:
   ```bash
   python -m shadow_uefi firmware.bin --baseline baseline.json --output-md diff.md
   ```

The baseline file should be a JSON export from a previous run (the `inventory` object). When no baseline is provided, the tool self-baselines the current image so you can generate an initial snapshot without spurious diffs.

## Project Structure

- `shadow_uefi/ingestion.py` – source detection and metadata capture for firmware images.
- `shadow_uefi/parser.py` – deterministic pseudo-module extraction from firmware bytes.
- `shadow_uefi/baseline.py` – inventory comparison logic for new/missing/modified modules.
- `shadow_uefi/ai.py` – heuristic AI triage highlights for analyst review.
- `shadow_uefi/report.py` – JSON and Markdown report builders.
- `shadow_uefi/cli.py` – command-line entry point.

## Defensive Focus

Shadow-UEFI-Intel is built solely for inspection and defensive triage. It does not generate or embed shellcode, persistence, or exploit payloads.
