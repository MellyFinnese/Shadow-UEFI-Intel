use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;

use crate::baseline::collect_images;
use crate::image::summarize_image;
use crate::models::{Alert, Baseline, Severity, UefiImageSummary};

fn index_baseline(baseline: &Baseline) -> HashMap<String, &UefiImageSummary> {
    baseline
        .images
        .iter()
        .map(|image| {
            (
                image
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| image.path.display().to_string()),
                image,
            )
        })
        .collect()
}

fn compare_modules(
    baseline: &UefiImageSummary,
    current: &UefiImageSummary,
    alerts: &mut Vec<Alert>,
) {
    let max_len = baseline.modules.len().max(current.modules.len());

    for index in 0..max_len {
        let baseline_module = baseline.modules.get(index);
        let current_module = current.modules.get(index);

        match (baseline_module, current_module) {
            (Some(expected), Some(actual)) => {
                if expected.hash != actual.hash {
                    alerts.push(Alert {
                        image: current.path.clone(),
                        severity: Severity::Critical,
                        message: format!(
                            "module {index} hash changed ({} -> {})",
                            expected.hash, actual.hash
                        ),
                    });
                }
            }
            (None, Some(extra)) => alerts.push(Alert {
                image: current.path.clone(),
                severity: Severity::Warning,
                message: format!("new module detected at index {index} (hash {})", extra.hash),
            }),
            (Some(missing), None) => alerts.push(Alert {
                image: current.path.clone(),
                severity: Severity::Warning,
                message: format!("module {index} missing (expected hash {})", missing.hash),
            }),
            (None, None) => unreachable!(),
        }
    }
}

pub fn analyze_against_baseline(baseline: &Baseline, paths: &[PathBuf]) -> Result<Vec<Alert>> {
    let mut alerts = Vec::new();
    let baseline_index = index_baseline(baseline);
    let images = collect_images(paths)?;

    for path in images {
        let summary = summarize_image(path.clone())?;
        let key = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());

        match baseline_index.get(&key) {
            Some(reference) => compare_modules(reference, &summary, &mut alerts),
            None => alerts.push(Alert {
                image: path.clone(),
                severity: Severity::Info,
                message: "image not present in baseline; recording for review".to_string(),
            }),
        }
    }

    if alerts.is_empty() {
        alerts.push(Alert {
            image: PathBuf::from("-"),
            severity: Severity::Info,
            message: "no suspicious changes detected".to_string(),
        });
    }

    Ok(alerts)
}
