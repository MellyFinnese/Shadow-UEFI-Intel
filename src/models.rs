use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UefiModuleFingerprint {
    pub index: usize,
    pub offset: usize,
    pub length: usize,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UefiImageSummary {
    pub path: PathBuf,
    pub size: u64,
    pub hash: String,
    pub modules: Vec<UefiModuleFingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub images: Vec<UefiImageSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub image: PathBuf,
    pub severity: Severity,
    pub message: String,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}
