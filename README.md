# Shadow-UEFI-Intel

UEFI / firmware inspection toolkit that parses images, baselines modules, and uses an AI layer to flag suspicious changes for human review. Defensive intel only.

## Overview
Shadow-UEFI-Intel streamlines firmware hygiene by combining deterministic parsing with an AI triage layer. The toolkit ingests UEFI images, builds reproducible baselines of modules and configuration, and highlights drift so analysts can focus on high-impact anomalies rather than manual diffing.

## Core capabilities
- **UEFI image parsing:** Extract and normalize firmware volumes, file systems, and drivers for repeatable analysis.
- **Baseline generation:** Snapshot module hashes, metadata, and configuration knobs to form a trusted reference set.
- **AI-assisted triage:** Prioritize changes by risk using a scoring model tuned for defensive use cases.
- **Explainable diffs:** Produce human-readable reports that trace why a module was flagged.
- **Audit-friendly workflows:** Preserve evidence artifacts and timestamps to support review or escalation.

## Analysis workflow
1. **Ingest**: Point the toolkit at a firmware image or physical dump and collect normalized artifacts.
2. **Baseline**: Create or load a known-good profile for the platform or firmware version under review.
3. **Compare**: Run the diff engine to surface module additions, removals, or mutations against the baseline.
4. **Triage**: Let the AI layer prioritize suspicious changes and provide rationale for each finding.
5. **Report**: Export results for peer review or case tracking with links back to supporting evidence.

## Operating principles
- **Defensive intelligence only:** All capabilities are scoped for detection, validation, and hardening workflows.
- **Reproducibility:** Every parsing and scoring step should be deterministic given the same inputs and config.
- **Transparency:** Findings must be explainable; opaque scores without context are insufficient.

## Roadmap
- Parser modules for common vendor layouts (AMI, Insyde, Phoenix, Coreboot).
- Signature and policy checks for Secure Boot, measured boot, and firmware protections.
- Integration hooks for offline AI models to keep analysis air-gapped.
- CLI and API surfaces for CI/CD or lab automation.

## Contributing
Issues and PRs focused on defensive detection, validation, or documentation improvements are welcome. Please accompany changes with rationale and, when possible, reproducible test cases.
UEFI / firmware inspection toolkit that parses images, baselines modules, and uses an AI-like change detector to flag suspicious differences for human review.

## Features

- 🧭 Scans firmware images for embedded PE/COFF modules using a lightweight Rust parser.
- 🔐 Hashes the full image and each module with SHA-256 to provide integrity anchors.
- 📚 Creates portable JSON baselines of known-good firmware builds.
- 🚨 Compares new images against baselines to highlight new, missing, or modified modules with a suspicion score.
- 🧪 Ships with unit tests for the PE scanner to reduce false positives.

## Usage

```bash
# Inspect a firmware image (text output)
cargo run -- inspect /path/to/firmware.bin

# Inspect as JSON
cargo run -- inspect /path/to/firmware.bin --format json

# Create a baseline JSON file
cargo run -- baseline /path/to/firmware.bin --output baselines/known-good.json --label "Version 1.2.3"

# Compare a new image against the baseline
cargo run -- compare /path/to/new.bin --baseline baselines/known-good.json
```

The compare command prints a simple suspicion score alongside a breakdown of new, missing, and changed modules. Use the JSON output for pipeline integration.

## Pre-Boot Sandbox

Shadow-UEFI-Intel ships with a Unicorn-backed "pre-boot sandbox" that executes detected PE/COFF modules in a constrained x86_64 environment. The emulator mocks EFI_BOOT_SERVICES and SMRAM windows so obvious tampering attempts are surfaced even when hashes remain unchanged.

```bash
# Execute each detected module inside the sandbox with a 100k instruction budget
cargo run -- sandbox /path/to/firmware.bin --instruction-limit 200000
```

For every module the sandbox reports suspicious memory writes such as SMRAM pokes or EFI boot service hooks, along with notes on how the execution halted (instruction budget or emulator fault). This is useful for catching stealthy rootkit behaviors before boot.

## Development

- Requires Rust 1.77+ (edition 2024).
- Run tests with `cargo test`.
- The crate intentionally keeps parsing forgiving to avoid missing modules embedded at odd offsets; add stricter validation as needed for production deployments.
