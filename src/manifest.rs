#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ManifestEntry {
    pub parser: String,
    pub collection: String,
    pub artifact: String,
    pub args: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exported_records: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Manifest {
    pub input_zip: String,
    pub parser_families: Vec<String>,
    pub collections: Vec<String>,
    pub extracted_dir: String,
    pub results_dir: String,
    pub entries: Vec<ManifestEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opensearch_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opensearch_index: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exported_records: Option<usize>,
}

pub fn write_manifest(path: &Path, manifest: &Manifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create manifest directory {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(manifest)?;
    fs::write(path, json).with_context(|| format!("write manifest {}", path.display()))?;
    Ok(())
}

pub fn read_manifest(path: &Path) -> Result<Manifest> {
    let bytes = fs::read(path).with_context(|| format!("read manifest {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("decode manifest {}", path.display()))
}
