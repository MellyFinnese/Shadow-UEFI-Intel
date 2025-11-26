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
pub enum TriageMode {
    Heuristic,
    Llm,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageFinding {
    pub summary: String,
    pub score: u8,
    pub reasons: Vec<String>,
    pub next_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystNotes {
    pub top_suspicious_changes: Vec<String>,
    pub why_they_matter: Vec<String>,
    pub what_to_verify_next: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageOutcome {
    pub mode: TriageMode,
    pub findings: Vec<TriageFinding>,
    pub analyst_notes: Option<AnalystNotes>,
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

pub fn run_triage(report: &DiffReport, mode: TriageMode) -> TriageOutcome {
    match mode {
        TriageMode::Off => TriageOutcome {
            mode,
            findings: Vec::new(),
            analyst_notes: None,
        },
        TriageMode::Heuristic => heuristic_triage(report),
        TriageMode::Llm => llm_notes(report),
    }
}

fn heuristic_triage(report: &DiffReport) -> TriageOutcome {
    let mut findings = Vec::new();

    for module in &report.new_modules {
        findings.push(TriageFinding {
            summary: format!("New module at offset 0x{:08x}", module.offset),
            score: 80,
            reasons: vec![
                "Module hash not seen in baseline".to_string(),
                format!(
                    "Machine {} / subsystem {} unexpected",
                    module.machine, module.subsystem
                ),
            ],
            next_steps: vec![
                "Validate provenance of the new module".to_string(),
                "Check Secure Boot or vendor signatures".to_string(),
            ],
        });
    }

    for module in &report.missing_modules {
        findings.push(TriageFinding {
            summary: format!("Module missing at offset 0x{:08x}", module.offset),
            score: 70,
            reasons: vec![
                "Baseline expected this module hash".to_string(),
                "Removal could hide tampering or downgrades".to_string(),
            ],
            next_steps: vec![
                "Confirm removal is intentional via release notes".to_string(),
                "Inspect platform boot logs for load failures".to_string(),
            ],
        });
    }

    for change in &report.changed_modules {
        findings.push(TriageFinding {
            summary: format!(
                "Module changed (baseline 0x{:08x} -> current 0x{:08x})",
                change.baseline.offset, change.current.offset
            ),
            score: 72,
            reasons: vec![
                "Hash drifted between baseline and current image".to_string(),
                format!("Characteristics now {}", change.current.characteristics),
            ],
            next_steps: vec![
                "Diff the PE sections to confirm functional changes".to_string(),
                "Verify the current binary is signed and expected".to_string(),
            ],
        });
    }

    if findings.is_empty() {
        findings.push(TriageFinding {
            summary: "No suspicious changes detected by heuristics".to_string(),
            score: 0,
            reasons: vec!["Baseline and current modules align".to_string()],
            next_steps: vec!["Archive the report for audit".to_string()],
        });
    }

    TriageOutcome {
        mode: TriageMode::Heuristic,
        findings,
        analyst_notes: None,
    }
}

fn llm_notes(report: &DiffReport) -> TriageOutcome {
    let mut top_suspicious_changes = Vec::new();
    let mut why_they_matter = Vec::new();
    let mut what_to_verify_next = Vec::new();

    if report.changed_modules.is_empty()
        && report.new_modules.is_empty()
        && report.missing_modules.is_empty()
    {
        top_suspicious_changes.push("No structural differences vs. baseline".to_string());
        why_they_matter.push("Deterministic comparisons found no drift".to_string());
        what_to_verify_next.push("Proceed with standard boot validation only".to_string());
    } else {
        for change in &report.changed_modules {
            top_suspicious_changes.push(format!(
                "Module at 0x{:08x} changed hash (baseline 0x{:08x})",
                change.current.offset, change.baseline.offset
            ));
            why_they_matter
                .push("Hash drift can indicate repacked or patched DXE drivers".to_string());
            what_to_verify_next
                .push("Compare exports/imports to confirm behavior stability".to_string());
        }

        for module in &report.new_modules {
            top_suspicious_changes.push(format!(
                "New module inserted at 0x{:08x} (subsystem {})",
                module.offset, module.subsystem
            ));
            why_they_matter
                .push("New modules can introduce persistence or new attack surface".to_string());
            what_to_verify_next.push("Trace module origin and vendor signature chain".to_string());
        }

        for module in &report.missing_modules {
            top_suspicious_changes.push(format!(
                "Baseline module missing at 0x{:08x} (machine {})",
                module.offset, module.machine
            ));
            why_they_matter
                .push("Missing modules may disable protections or hide code".to_string());
            what_to_verify_next.push("Check boot logs for missing entry points".to_string());
        }
    }

    TriageOutcome {
        mode: TriageMode::Llm,
        findings: Vec::new(),
        analyst_notes: Some(AnalystNotes {
            top_suspicious_changes,
            why_they_matter,
            what_to_verify_next,
        }),
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
        resolve_rva: false,
        parse_attribute_certificates: false,
        reject_malformed: false,
        allow_trailing_bytes: true,
        ..Default::default()
    };
    let pe = goblin::pe::PE::parse_with_opts(&data[offset..], &parse_options).ok()?;
    let optional_header = pe.header.optional_header.as_ref()?;
    let size_of_image = optional_header.windows_fields.size_of_image as usize;
    let length = size_of_image.min(data.len().saturating_sub(offset));

    let module_bytes = &data[offset..offset + length];
    let hash = hash_bytes(module_bytes);
    let entry_point_rva = if optional_header.standard_fields.address_of_entry_point == 0 {
        0x200
    } else {
        optional_header.standard_fields.address_of_entry_point as u64
    };
    let image_base = optional_header.windows_fields.image_base.max(0x400000);
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
        machine: format_machine(pe.header.coff_header.machine),
        subsystem: format_subsystem(optional_header.windows_fields.subsystem),
        machine: header::machine_to_str(pe.header.coff_header.machine).to_string(),
        subsystem: header::subsystem_to_str(pe.header.optional_header.windows_fields.subsystem)
            .to_string(),
        characteristics: format!("0x{:x}", pe.header.coff_header.characteristics),
        entry_point,
        image_base,
        hash,
    })
}

fn format_machine(machine: u16) -> String {
    match machine {
        header::COFF_MACHINE_X86 => "x86".to_string(),
        header::COFF_MACHINE_X86_64 => "x86_64".to_string(),
        header::COFF_MACHINE_ARM64 => "arm64".to_string(),
        _ => header::machine_to_str(machine).to_ascii_lowercase(),
    }
}

fn format_subsystem(subsystem: u16) -> String {
    match subsystem {
        0 => "Windows CUI".to_string(),
        2 => "Windows CUI".to_string(),
        3 => "Windows CUI".to_string(),
        10 => "EFI Application".to_string(),
        11 => "EFI Boot Service Driver".to_string(),
        12 => "EFI Runtime Driver".to_string(),
        13 => "EFI ROM".to_string(),
        other => format!("subsystem-{}", other),
    }
}

fn dedup_overlapping(modules: &mut Vec<FirmwareModule>) {
    modules.sort_by_key(|m| m.offset);
    let mut deduped: Vec<FirmwareModule> = Vec::new();

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
