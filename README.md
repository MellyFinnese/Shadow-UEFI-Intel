# Shadow-UEFI-Intel

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

## Development

- Requires Rust 1.77+ (edition 2024).
- Run tests with `cargo test`.
- The crate intentionally keeps parsing forgiving to avoid missing modules embedded at odd offsets; add stricter validation as needed for production deployments.
