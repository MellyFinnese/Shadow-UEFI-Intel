use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use goblin::pe::{header, options::ParseOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

pub mod sandbox;
pub use sandbox::{
    SandboxConfig, SandboxEvent, SandboxEventKind, SandboxReport, run_module_sandbox,
    sandbox_firmware_modules,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareModule {
    pub offset: u64,
    pub length: u32,
    pub machine: String,
    pub subsystem: String,
    pub characteristics: String,
    pub entry_point: u64,
    pub image_base: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareScan {
    pub firmware_path: PathBuf,
    pub firmware_hash: String,
    pub modules: Vec<FirmwareModule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub firmware_hash: String,
    pub modules: Vec<FirmwareModule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub baseline_label: String,
    pub baseline_created_at: DateTime<Utc>,
    pub firmware_hash: String,
    pub new_modules: Vec<FirmwareModule>,
    pub missing_modules: Vec<FirmwareModule>,
    pub changed_modules: Vec<ModuleChange>,
    pub suspicious_score: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleChange {
    pub baseline: FirmwareModule,
    pub current: FirmwareModule,
}

#[derive(thiserror::Error, Debug)]
pub enum FirmwareError {
    #[error("firmware image '{path}' is empty")]
    EmptyImage { path: String },
}

pub fn scan_firmware(path: impl AsRef<Path>) -> Result<FirmwareScan> {
    let path = path.as_ref();
    let data = fs::read(path)
        .with_context(|| format!("Failed to read firmware image: {}", path.display()))?;
    if data.is_empty() {
        return Err(FirmwareError::EmptyImage {
            path: path.display().to_string(),
        }
        .into());
    }

    let firmware_hash = hash_bytes(&data);
    let modules = extract_modules(&data);

    Ok(FirmwareScan {
        firmware_path: path.to_path_buf(),
        firmware_hash,
        modules,
    })
}

pub fn build_baseline(scan: &FirmwareScan, label: Option<&str>) -> Baseline {
    let label = label
        .map(|l| l.to_string())
        .unwrap_or_else(|| format!("baseline-{}", scan.firmware_path.display()));

    Baseline {
        label,
        created_at: Utc::now(),
        firmware_hash: scan.firmware_hash.clone(),
        modules: scan.modules.clone(),
    }
}

pub fn compare_against_baseline(baseline: &Baseline, scan: &FirmwareScan) -> DiffReport {
    let mut baseline_map: HashMap<String, &FirmwareModule> = HashMap::new();
    for module in &baseline.modules {
        baseline_map.insert(module.hash.clone(), module);
    }

    let mut current_map: HashMap<String, &FirmwareModule> = HashMap::new();
    for module in &scan.modules {
        current_map.insert(module.hash.clone(), module);
    }

    let mut new_modules = Vec::new();
    let mut missing_modules = Vec::new();
    let mut changed_modules = Vec::new();

    for module in &scan.modules {
        if baseline_map.contains_key(&module.hash) {
            continue;
        }

        if let Some(original) = find_closest_match(module, &baseline.modules) {
            changed_modules.push(ModuleChange {
                baseline: original.clone(),
                current: module.clone(),
            });
        } else {
            new_modules.push(module.clone());
        }
    }

    for module in &baseline.modules {
        if current_map.contains_key(&module.hash) {
            continue;
        }

        if find_closest_match(module, &scan.modules).is_none() {
            missing_modules.push(module.clone());
        }
    }

    let suspicious_score = new_modules.len() + missing_modules.len() + changed_modules.len();

    DiffReport {
        baseline_label: baseline.label.clone(),
        baseline_created_at: baseline.created_at,
        firmware_hash: scan.firmware_hash.clone(),
        new_modules,
        missing_modules,
        changed_modules,
        suspicious_score,
    }
}

pub fn save_baseline(path: impl AsRef<Path>, baseline: &Baseline) -> Result<()> {
    let json = serde_json::to_string_pretty(baseline)?;
    fs::write(path, json).context("failed to write baseline file")?;
    Ok(())
}

pub fn load_baseline(path: impl AsRef<Path>) -> Result<Baseline> {
    let data = fs::read_to_string(&path)
        .with_context(|| format!("failed to read baseline {}", path.as_ref().display()))?;
    let baseline: Baseline =
        serde_json::from_str(&data).context("failed to parse baseline JSON")?;
    Ok(baseline)
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn extract_modules(data: &[u8]) -> Vec<FirmwareModule> {
    let mut modules = Vec::new();
    let mut idx = 0usize;

    while idx + 2 < data.len() {
        if data[idx] != b'M' || data[idx + 1] != b'Z' {
            idx += 1;
            continue;
        }

        if let Some(module) = parse_pe_image(data, idx) {
            modules.push(module);
        }

        idx += 1;
    }

    dedup_overlapping(&mut modules);
    modules.sort_by_key(|m| m.offset);
    modules
}

fn parse_pe_image(data: &[u8], offset: usize) -> Option<FirmwareModule> {
    let mz_header_size = 0x40; // minimal size for e_lfanew presence
    if offset + mz_header_size >= data.len() {
        return None;
    }

    let lfanew_bytes = &data[offset + 0x3c..offset + 0x40];
    let lfanew = u32::from_le_bytes(lfanew_bytes.try_into().ok()?);
    let pe_offset = offset.checked_add(lfanew as usize)?;
    if pe_offset + 4 >= data.len() {
        return None;
    }

    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }

    let parse_options = ParseOptions {
        reject_malformed: false,
        allow_trailing_bytes: true,
        ..Default::default()
    };
    let pe = goblin::pe::PE::parse_with_opts(&data[offset..], &parse_options).ok()?;
    let size_of_image = pe.header.optional_header.windows_fields.size_of_image as usize;
    let length = size_of_image.min(data.len().saturating_sub(offset));

    let module_bytes = &data[offset..offset + length];
    let hash = hash_bytes(module_bytes);
    let entry_point_rva = pe
        .header
        .optional_header
        .standard_fields
        .address_of_entry_point as u64;
    let image_base = pe.header.optional_header.windows_fields.image_base;
    let entry_point = image_base + entry_point_rva;

    Some(FirmwareModule {
        offset: offset as u64,
        length: length as u32,
        machine: header::machine_to_str(pe.header.coff_header.machine).to_string(),
        subsystem: header::subsystem_to_str(pe.header.optional_header.windows_fields.subsystem)
            .to_string(),
        characteristics: format!("0x{:x}", pe.header.coff_header.characteristics),
        entry_point,
        image_base,
        hash,
    })
}

fn dedup_overlapping(modules: &mut Vec<FirmwareModule>) {
    modules.sort_by_key(|m| m.offset);
    let mut deduped = Vec::new();

    for module in modules.drain(..) {
        if let Some(last) = deduped.last() {
            let last_end = last.offset + last.length as u64;
            if module.offset < last_end {
                continue;
            }
        }
        deduped.push(module);
    }

    *modules = deduped;
}

fn find_closest_match<'a>(
    module: &FirmwareModule,
    candidates: &'a [FirmwareModule],
) -> Option<&'a FirmwareModule> {
    candidates
        .iter()
        .filter(|other| other.machine == module.machine && other.subsystem == module.subsystem)
        .min_by_key(|other| (module.length as i64 - other.length as i64).abs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_empty_scan_for_random_data() {
        let data = vec![0u8; 128];
        assert!(extract_modules(&data).is_empty());
    }

    #[test]
    fn detects_synthetic_pe_image() {
        // Construct a minimal synthetic PE image with MZ header and PE signature.
        let mut data = vec![0u8; 512];
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew at 0x3c pointing to 0x80
        data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        // Minimal COFF header
        data[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // machine x86_64
        data[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // size of optional header
        // Optional header magic (PE32+)
        data[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        // Address of entry point
        data[0xb0..0xb4].copy_from_slice(&0x200u32.to_le_bytes());
        // Image base
        data[0xb8..0xc0].copy_from_slice(&0x400000u64.to_le_bytes());
        // Subsystem
        data[0xc4..0xc6].copy_from_slice(&0x2u16.to_le_bytes());
        // Size of image
        data[0xd0..0xd4].copy_from_slice(&0x2000u32.to_le_bytes());

        let modules = extract_modules(&data);
        assert_eq!(modules.len(), 1);
        let module = &modules[0];
        assert_eq!(module.offset, 0);
        assert_eq!(module.machine, "x86_64");
        assert_eq!(module.subsystem, "Windows CUI");
        assert_eq!(module.entry_point, 0x400200);
    }
}
