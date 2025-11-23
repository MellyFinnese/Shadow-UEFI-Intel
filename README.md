# Shadow-UEFI-Intel

UEFI / firmware inspection toolkit rewritten in Rust. The CLI can parse firmware images, create a baseline of known-good modules, and analyze new images for changes that warrant human review.

## Features

- **Baseline generation:** Hashes every 64 KiB module-sized chunk in a firmware image and stores the summary as JSON.
- **Analysis:** Compares new images to an existing baseline and flags added, missing, or modified modules with severity labels.
- **Inspection:** Quickly prints module-level hashes for a single image.

## Usage

1. **Build the tool**

```bash
cargo build --release
```

2. **Create a baseline**

```bash
./target/release/shadow-uefi-intel baseline --output baseline.json path/to/firmware.bin
```

You can pass multiple files or directories. All files discovered in the provided paths are included in the baseline.

3. **Analyze new firmware against the baseline**

```bash
./target/release/shadow-uefi-intel analyze --baseline baseline.json path/to/new/firmware.bin
```

4. **Inspect a single image**

```bash
./target/release/shadow-uefi-intel inspect path/to/firmware.bin
```

## Baseline format

Baselines are stored as pretty-printed JSON with a timestamp, overall image hashes, and per-chunk module fingerprints. This keeps the format simple for scripting while remaining resilient to changes.
