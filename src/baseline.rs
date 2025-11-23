use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use walkdir::WalkDir;

use crate::image::summarize_image;
use crate::models::{Baseline, UefiImageSummary};

pub fn collect_images(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut images = Vec::new();

    for path in paths {
        if path.is_file() {
            images.push(path.clone());
        } else if path.is_dir() {
            for entry in WalkDir::new(path) {
                let entry = entry?;
                if entry.file_type().is_file() {
                    images.push(entry.path().to_path_buf());
                }
            }
        }
    }

    if images.is_empty() {
        anyhow::bail!("no firmware images found");
    }

    Ok(images)
}

pub fn create_baseline(images: &[PathBuf]) -> Result<Baseline> {
    let summaries: Vec<UefiImageSummary> = images
        .iter()
        .map(|path| summarize_image(path.clone()))
        .collect::<Result<_>>()?;

    Ok(Baseline {
        created_at: chrono::Utc::now(),
        images: summaries,
    })
}

pub fn write_baseline(baseline: &Baseline, output: &Path) -> Result<()> {
    let payload = serde_json::to_string_pretty(baseline)?;
    fs::write(output, payload)
        .with_context(|| format!("failed to write baseline to {}", output.display()))?;
    Ok(())
}

pub fn read_baseline(path: &Path) -> Result<Baseline> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline from {}", path.display()))?;
    let baseline: Baseline = serde_json::from_str(&contents)?;
    Ok(baseline)
}
