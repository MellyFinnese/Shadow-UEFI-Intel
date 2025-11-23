use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

use crate::models::{UefiImageSummary, UefiModuleFingerprint};

const MODULE_CHUNK_SIZE: usize = 64 * 1024;

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_file(path: &Path) -> Result<(String, Vec<u8>)> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read image from {}", path.display()))?;
    let hash = hash_bytes(&bytes);
    Ok((hash, bytes))
}

fn module_fingerprints(bytes: &[u8]) -> Vec<UefiModuleFingerprint> {
    bytes
        .chunks(MODULE_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| UefiModuleFingerprint {
            index,
            offset: index * MODULE_CHUNK_SIZE,
            length: chunk.len(),
            hash: hash_bytes(chunk),
        })
        .collect()
}

pub fn summarize_image(path: PathBuf) -> Result<UefiImageSummary> {
    let (hash, bytes) = hash_file(&path)?;
    let metadata = fs::metadata(&path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;

    Ok(UefiImageSummary {
        path,
        size: metadata.len(),
        hash,
        modules: module_fingerprints(&bytes),
    })
}
