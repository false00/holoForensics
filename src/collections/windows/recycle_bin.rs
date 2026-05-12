#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::mem::size_of;
#[cfg(target_os = "windows")]
use std::os::windows::{ffi::OsStrExt, fs::MetadataExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::collection_metadata;
use crate::collections::windows::{usn_journal, vss};
use crate::runtime_support;

const RECYCLE_BIN_COLLECTION_SCHEMA: &str = "windows_recycle_bin_info2_collection_v1";
const RECYCLE_BIN_COLLECTOR_NAME: &str = "windows_recycle_bin";
const RECYCLE_BIN_JSONL_NAME: &str = "recycle_bin_manifest.jsonl";
#[cfg(target_os = "windows")]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

#[derive(Debug, Clone, Args)]
pub struct RecycleBinCollectCli {
    #[arg(long, help = "NTFS volume, for example C:")]
    pub volume: String,

    #[arg(
        long = "out-dir",
        help = "Output root directory for collected Recycle Bin evidence"
    )]
    pub out_dir: PathBuf,

    #[arg(
        long,
        help = "Optional collection manifest path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_recycle_bin/manifest.json"
    )]
    pub manifest: Option<PathBuf>,

    #[arg(
        long = "artifact-manifest",
        help = "Optional JSONL artifact manifest path; defaults to <out-dir>/<volume>/recycle_bin_manifest.jsonl"
    )]
    pub artifact_manifest: Option<PathBuf>,

    #[arg(
        long = "collection-log",
        help = "Optional collection log path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_recycle_bin/collection.log"
    )]
    pub collection_log: Option<PathBuf>,

    #[arg(
        long,
        help = "Optional technical log path; defaults to ~/.holo-forensics/holo-forensics.log"
    )]
    pub diagnostic_log: Option<PathBuf>,

    #[arg(
        long,
        help = "Prompt for UAC elevation and relaunch the collector if the current process is not elevated"
    )]
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct RecycleBinCollectRequest {
    pub volume: String,
    pub out_dir: PathBuf,
    pub manifest: Option<PathBuf>,
    pub artifact_manifest: Option<PathBuf>,
    pub collection_log: Option<PathBuf>,
    pub diagnostic_log: Option<PathBuf>,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct RecycleBinCollectSummary {
    pub volume: String,
    pub output_root: PathBuf,
    pub manifest_path: PathBuf,
    pub artifact_manifest_path: PathBuf,
    pub collection_log_path: PathBuf,
    pub staged_paths: Vec<PathBuf>,
    pub file_records: Vec<RecycleBinCollectedFile>,
    pub failures: Vec<RecycleBinCollectionFailure>,
}

#[derive(Debug, Clone)]
pub struct RecycleBinProgress {
    pub progress_value: f32,
    pub detail: String,
    pub progress_text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CollectionStatus {
    Succeeded,
    CompletedWithErrors,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CollectorMetadata {
    name: String,
    version: String,
    language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShadowCopyMetadata {
    created: bool,
    deleted: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    shared: bool,
    id: String,
    device_object: String,
    context: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecycleBinRootKind {
    Modern,
    Legacy,
}

impl RecycleBinRootKind {
    fn root_name(self) -> &'static str {
        match self {
            Self::Modern => "$Recycle.Bin",
            Self::Legacy => "Recycler",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecycleBinArtifactKind {
    MetadataI,
    PayloadR,
    Info2,
    RecycledDirectoryMember,
    LegacyRenamed,
    DesktopIni,
    RootFile,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecycleBinCollectedFile {
    pub archive_path: String,
    pub source_volume: String,
    pub source_path: String,
    pub destination_path: String,
    pub vss_path: String,
    pub root_kind: RecycleBinRootKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recycle_sid: Option<String>,
    pub artifact_kind: RecycleBinArtifactKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pair_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
    pub is_directory: bool,
    pub file_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessed_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file_attributes: Option<u32>,
    pub source_sha256: String,
    pub sha256: String,
    pub collection_time_utc: String,
    pub copy_status: String,
}

#[derive(Debug, Clone, Serialize)]
struct RecycleBinArtifactManifestRecord {
    source_volume: String,
    source_path: String,
    destination_path: String,
    vss_path: String,
    root_kind: RecycleBinRootKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    recycle_sid: Option<String>,
    artifact_kind: RecycleBinArtifactKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pair_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extension: Option<String>,
    is_directory: bool,
    file_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accessed_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_file_attributes: Option<u32>,
    sha256: String,
    collection_time_utc: String,
}

impl From<&RecycleBinCollectedFile> for RecycleBinArtifactManifestRecord {
    fn from(value: &RecycleBinCollectedFile) -> Self {
        Self {
            source_volume: value.source_volume.clone(),
            source_path: value.source_path.clone(),
            destination_path: value.destination_path.clone(),
            vss_path: value.vss_path.clone(),
            root_kind: value.root_kind,
            recycle_sid: value.recycle_sid.clone(),
            artifact_kind: value.artifact_kind,
            pair_id: value.pair_id.clone(),
            extension: value.extension.clone(),
            is_directory: value.is_directory,
            file_size: value.file_size,
            created_time: value.created_time.clone(),
            modified_time: value.modified_time.clone(),
            accessed_time: value.accessed_time.clone(),
            source_file_attributes: value.source_file_attributes,
            sha256: value.sha256.clone(),
            collection_time_utc: value.collection_time_utc.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecycleBinCollectionFailure {
    pub source_path: String,
    pub vss_path: String,
    pub archive_path: String,
    pub operation: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecycleBinCollectionManifest {
    metadata_schema: String,
    artifact_type: String,
    artifact_name: String,
    volume: String,
    collection_status: CollectionStatus,
    collection_start_utc: String,
    collection_end_utc: String,
    elevation: bool,
    collector: CollectorMetadata,
    transaction_safe: bool,
    source_root: String,
    source_roots: Vec<String>,
    artifact_manifest_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    privileges_enabled: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shadow_copy: Option<ShadowCopyMetadata>,
    total_roots_present: usize,
    total_files_found: usize,
    total_files_copied: usize,
    total_files_failed: usize,
    files: Vec<RecycleBinCollectedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    failures: Vec<RecycleBinCollectionFailure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct PlannedRecycleBinFile {
    source_path: PathBuf,
    live_path: String,
    archive_path: PathBuf,
    root_kind: RecycleBinRootKind,
    recycle_sid: Option<String>,
    artifact_kind: RecycleBinArtifactKind,
    pair_id: Option<String>,
    extension: Option<String>,
}

struct RecycleBinPlan {
    files: Vec<PlannedRecycleBinFile>,
    warnings: Vec<String>,
    roots_present: usize,
}

#[derive(Debug, Clone)]
struct PairIdentity {
    pair_id: String,
    extension: Option<String>,
}

pub fn run(args: &RecycleBinCollectCli) -> Result<()> {
    let summary = collect(&RecycleBinCollectRequest {
        volume: args.volume.clone(),
        out_dir: args.out_dir.clone(),
        manifest: args.manifest.clone(),
        artifact_manifest: args.artifact_manifest.clone(),
        collection_log: args.collection_log.clone(),
        diagnostic_log: args.diagnostic_log.clone(),
        elevate: args.elevate,
    })?;
    println!(
        "Collected {} Recycle Bin files.",
        summary.file_records.len()
    );
    println!("Failed {} Recycle Bin files.", summary.failures.len());
    println!(
        "Artifact manifest: {}",
        summary.artifact_manifest_path.display()
    );
    println!("Manifest: {}", summary.manifest_path.display());
    println!("Collection log: {}", summary.collection_log_path.display());
    Ok(())
}

pub fn collect(request: &RecycleBinCollectRequest) -> Result<RecycleBinCollectSummary> {
    let mut reporter = |_| {};
    collect_with_progress(request, &mut reporter)
}

pub fn collect_with_progress(
    request: &RecycleBinCollectRequest,
    reporter: &mut dyn FnMut(RecycleBinProgress),
) -> Result<RecycleBinCollectSummary> {
    validate_request(request)?;
    let volume = usn_journal::normalize_volume(&request.volume)?;
    let manifest_path = request
        .manifest
        .clone()
        .unwrap_or(default_manifest_path(&request.out_dir, &volume)?);
    let artifact_manifest_path = request
        .artifact_manifest
        .clone()
        .unwrap_or(default_artifact_manifest_path(&request.out_dir, &volume)?);
    let collection_log_path = request
        .collection_log
        .clone()
        .unwrap_or(default_collection_log_path(&request.out_dir, &volume)?);

    if request.elevate && !is_process_elevated() {
        reporter(RecycleBinProgress {
            progress_value: 0.03,
            detail: "Waiting for elevation approval.".to_string(),
            progress_text: "UAC".to_string(),
        });
        relaunch_elevated(request)?;
        return load_existing_summary(
            &volume,
            &request.out_dir,
            &manifest_path,
            &artifact_manifest_path,
            &collection_log_path,
        );
    }

    let shadow_copy = vss::create_shadow_copy(&request.volume)?;
    let result = collect_from_shadow_copy(request, &shadow_copy, false, reporter);
    let delete_result = vss::delete_shadow_copy(&shadow_copy.id)
        .with_context(|| format!("delete Recycle Bin shadow copy {}", shadow_copy.id));
    match (result, delete_result) {
        (Ok(summary), Ok(())) => {
            mark_shadow_deleted(&summary.manifest_path)?;
            Ok(summary)
        }
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(delete_error)) => Err(error.context(format!(
            "also failed to delete Recycle Bin shadow copy {}: {delete_error:#}",
            shadow_copy.id
        ))),
    }
}

pub fn collect_with_progress_using_shadow_copy(
    request: &RecycleBinCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    reporter: &mut dyn FnMut(RecycleBinProgress),
) -> Result<RecycleBinCollectSummary> {
    validate_request(request)?;
    collect_from_shadow_copy(request, shadow_copy, true, reporter)
}

pub fn default_manifest_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_manifest_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_RECYCLE_BIN_COLLECTOR,
    )
}

pub fn default_artifact_manifest_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    Ok(output_root
        .join(volume_archive_root(volume)?)
        .join(RECYCLE_BIN_JSONL_NAME))
}

pub fn default_collection_log_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_log_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_RECYCLE_BIN_COLLECTOR,
    )
}

pub fn default_diagnostic_log_path(_output_root: &Path) -> PathBuf {
    runtime_support::technical_log_path()
}

fn validate_request(request: &RecycleBinCollectRequest) -> Result<()> {
    let _ = usn_journal::normalize_volume(&request.volume)?;
    if request.out_dir.as_os_str().is_empty() {
        bail!("--out-dir must not be empty");
    }
    Ok(())
}

fn collect_from_shadow_copy(
    request: &RecycleBinCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    shared_shadow_copy: bool,
    reporter: &mut dyn FnMut(RecycleBinProgress),
) -> Result<RecycleBinCollectSummary> {
    let volume = usn_journal::normalize_volume(&request.volume)?;
    let manifest_path = request
        .manifest
        .clone()
        .unwrap_or(default_manifest_path(&request.out_dir, &volume)?);
    let artifact_manifest_path = request
        .artifact_manifest
        .clone()
        .unwrap_or(default_artifact_manifest_path(&request.out_dir, &volume)?);
    let collection_log_path = request
        .collection_log
        .clone()
        .unwrap_or(default_collection_log_path(&request.out_dir, &volume)?);

    fs::create_dir_all(&request.out_dir)
        .with_context(|| format!("create output root {}", request.out_dir.display()))?;
    reporter(RecycleBinProgress {
        progress_value: 0.05,
        detail: format!("Enumerating Recycle Bin roots on {volume}."),
        progress_text: "Enumerating".to_string(),
    });

    let start_time = Utc::now();
    let source_root = vss::shadow_copy_source_root(&shadow_copy.device_object);
    let mut warnings = Vec::new();
    let mut privileges_enabled = Vec::new();
    for privilege in [
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeSecurityPrivilege",
    ] {
        match enable_privilege(privilege) {
            Ok(()) => privileges_enabled.push(privilege.to_string()),
            Err(error) => warnings.push(format!("could not enable {privilege}: {error:#}")),
        }
    }

    let RecycleBinPlan {
        files: planned,
        warnings: plan_warnings,
        roots_present,
    } = plan_recycle_bin_files(&volume, &source_root)?;
    warnings.extend(plan_warnings);

    let mut staged_paths = Vec::new();
    let mut file_records = Vec::new();
    let mut failures = Vec::new();
    let total = planned.len();

    for (index, planned_file) in planned.into_iter().enumerate() {
        let archive_name = normalize_archive_path_string(&planned_file.archive_path);
        let destination_path = request.out_dir.join(&planned_file.archive_path);
        reporter(RecycleBinProgress {
            progress_value: 0.08 + (0.80 * progress_fraction(index, total)),
            detail: format!("Copying {archive_name}"),
            progress_text: format!("{index} / {total} files"),
        });

        match copy_recycle_bin_file(&volume, &planned_file, &destination_path) {
            Ok(record) => {
                staged_paths.push(destination_path);
                file_records.push(record);
            }
            Err(error) => failures.push(RecycleBinCollectionFailure {
                source_path: planned_file.live_path,
                vss_path: planned_file.source_path.display().to_string(),
                archive_path: archive_name,
                operation: "copy_hash_verify".to_string(),
                error: error.to_string(),
            }),
        }
    }

    reporter(RecycleBinProgress {
        progress_value: 0.90,
        detail: "Writing Recycle Bin JSONL manifest.".to_string(),
        progress_text: "JSONL".to_string(),
    });
    write_artifact_manifest(&artifact_manifest_path, &file_records)?;
    staged_paths.push(artifact_manifest_path.clone());

    reporter(RecycleBinProgress {
        progress_value: 0.94,
        detail: "Writing Recycle Bin manifest and collection log.".to_string(),
        progress_text: "Manifest".to_string(),
    });

    let end_time = Utc::now();
    let manifest = RecycleBinCollectionManifest {
        metadata_schema: RECYCLE_BIN_COLLECTION_SCHEMA.to_string(),
        artifact_type: "windows_recycle_bin_info2_collection".to_string(),
        artifact_name: "Windows Recycle Bin".to_string(),
        volume: volume.clone(),
        collection_status: if failures.is_empty() {
            CollectionStatus::Succeeded
        } else {
            CollectionStatus::CompletedWithErrors
        },
        collection_start_utc: start_time.to_rfc3339_opts(SecondsFormat::Nanos, true),
        collection_end_utc: end_time.to_rfc3339_opts(SecondsFormat::Nanos, true),
        elevation: is_process_elevated(),
        collector: CollectorMetadata {
            name: RECYCLE_BIN_COLLECTOR_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            language: "rust".to_string(),
        },
        transaction_safe: true,
        source_root: source_root.display().to_string(),
        source_roots: recycle_bin_source_roots(&volume),
        artifact_manifest_path: relative_output_path_string(
            &request.out_dir,
            &artifact_manifest_path,
        ),
        privileges_enabled,
        shadow_copy: Some(ShadowCopyMetadata {
            created: !shared_shadow_copy,
            deleted: false,
            shared: shared_shadow_copy,
            id: shadow_copy.id.clone(),
            device_object: shadow_copy.device_object.clone(),
            context: shadow_copy.context.clone(),
        }),
        total_roots_present: roots_present,
        total_files_found: total,
        total_files_copied: file_records.len(),
        total_files_failed: failures.len(),
        files: file_records.clone(),
        failures: failures.clone(),
        warnings,
    };

    write_manifest(&manifest_path, &manifest)?;
    write_collection_log(&collection_log_path, &manifest)?;
    staged_paths.push(manifest_path.clone());
    staged_paths.push(collection_log_path.clone());

    reporter(RecycleBinProgress {
        progress_value: 1.0,
        detail: format!(
            "Copied {} of {} Recycle Bin files from {volume}.",
            file_records.len(),
            total
        ),
        progress_text: format!("{} copied, {} failed", file_records.len(), failures.len()),
    });

    Ok(RecycleBinCollectSummary {
        volume,
        output_root: request.out_dir.clone(),
        manifest_path,
        artifact_manifest_path,
        collection_log_path,
        staged_paths,
        file_records,
        failures,
    })
}

fn load_existing_summary(
    volume: &str,
    output_root: &Path,
    manifest_path: &Path,
    artifact_manifest_path: &Path,
    collection_log_path: &Path,
) -> Result<RecycleBinCollectSummary> {
    let bytes = fs::read(manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let manifest: RecycleBinCollectionManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode manifest {}", manifest_path.display()))?;
    let mut staged_paths = manifest
        .files
        .iter()
        .map(|record| materialize_output_path(output_root, &record.archive_path))
        .collect::<Vec<_>>();
    staged_paths.push(materialize_output_path(
        output_root,
        &manifest.artifact_manifest_path,
    ));
    staged_paths.push(manifest_path.to_path_buf());
    staged_paths.push(collection_log_path.to_path_buf());
    Ok(RecycleBinCollectSummary {
        volume: volume.to_string(),
        output_root: output_root.to_path_buf(),
        manifest_path: manifest_path.to_path_buf(),
        artifact_manifest_path: artifact_manifest_path.to_path_buf(),
        collection_log_path: collection_log_path.to_path_buf(),
        staged_paths,
        file_records: manifest.files,
        failures: manifest.failures,
    })
}

fn plan_recycle_bin_files(volume: &str, source_root: &Path) -> Result<RecycleBinPlan> {
    let normalized_volume = usn_journal::normalize_volume(volume)?;
    let archive_root = volume_archive_root(&normalized_volume)?;
    let mut planned = Vec::new();
    let mut warnings = Vec::new();
    let mut archive_paths = BTreeSet::new();
    let mut roots_present = 0usize;

    for root_kind in [RecycleBinRootKind::Modern, RecycleBinRootKind::Legacy] {
        let source_dir = source_root.join(root_kind.root_name());
        if !source_dir.exists() {
            continue;
        }
        if !source_dir.is_dir() {
            warnings.push(format!(
                "Recycle Bin root was not a directory: {}",
                source_dir.display()
            ));
            continue;
        }
        if is_reparse_or_symlink(&source_dir) {
            warnings.push(format!(
                "skipped reparse/symlink Recycle Bin root: {}",
                source_dir.display()
            ));
            continue;
        }

        roots_present += 1;
        let archive_dir = archive_root.join(root_kind.root_name());
        let live_dir = format!(r"{}\{}", normalized_volume, root_kind.root_name());
        collect_recycle_bin_directory(
            &source_dir,
            &source_dir,
            &archive_dir,
            &live_dir,
            root_kind,
            &mut planned,
            &mut archive_paths,
            &mut warnings,
        )?;
    }

    if roots_present == 0 {
        warnings.push(format!(
            "no Recycle Bin roots were present in snapshot for {}",
            normalized_volume
        ));
    }

    planned.sort_by_key(|file| file.archive_path.display().to_string().to_ascii_lowercase());
    Ok(RecycleBinPlan {
        files: planned,
        warnings,
        roots_present,
    })
}

fn collect_recycle_bin_directory(
    root_dir: &Path,
    current_dir: &Path,
    archive_root: &Path,
    live_root: &str,
    root_kind: RecycleBinRootKind,
    planned: &mut Vec<PlannedRecycleBinFile>,
    archive_paths: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let entries = match fs::read_dir(current_dir) {
        Ok(entries) => entries,
        Err(error) => {
            warnings.push(format!(
                "could not enumerate {}: {error}",
                current_dir.display()
            ));
            return Ok(());
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(format!(
                    "could not read entry in {}: {error}",
                    current_dir.display()
                ));
                continue;
            }
        };

        let source_path = entry.path();
        if source_path.is_dir() {
            if is_reparse_or_symlink(&source_path) {
                warnings.push(format!(
                    "skipped reparse/symlink directory: {}",
                    source_path.display()
                ));
                continue;
            }

            collect_recycle_bin_directory(
                root_dir,
                &source_path,
                archive_root,
                live_root,
                root_kind,
                planned,
                archive_paths,
                warnings,
            )?;
            continue;
        }
        if !source_path.is_file() {
            continue;
        }
        if is_reparse_or_symlink(&source_path) {
            warnings.push(format!(
                "skipped reparse/symlink file: {}",
                source_path.display()
            ));
            continue;
        }

        let Ok(relative_path) = source_path.strip_prefix(root_dir) else {
            warnings.push(format!(
                "could not derive relative Recycle Bin path for {}",
                source_path.display()
            ));
            continue;
        };
        let archive_path = archive_root.join(relative_path);
        let normalized_archive_path = normalize_archive_path_string(&archive_path);
        if !archive_paths.insert(normalized_archive_path) {
            continue;
        }

        let classification =
            classify_recycle_bin_item(root_kind, relative_path, &entry.file_name());
        planned.push(PlannedRecycleBinFile {
            source_path: source_path.clone(),
            live_path: join_live_path(live_root, relative_path),
            archive_path,
            root_kind,
            recycle_sid: classification.recycle_sid,
            artifact_kind: classification.artifact_kind,
            pair_id: classification.pair_id,
            extension: classification.extension,
        });
    }

    Ok(())
}

struct RecycleBinClassification {
    recycle_sid: Option<String>,
    artifact_kind: RecycleBinArtifactKind,
    pair_id: Option<String>,
    extension: Option<String>,
}

fn classify_recycle_bin_item(
    root_kind: RecycleBinRootKind,
    relative_path: &Path,
    file_name: &std::ffi::OsStr,
) -> RecycleBinClassification {
    let components = relative_path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>();
    let file_name = file_name.to_string_lossy().to_string();
    let extension = file_extension_with_dot(&file_name);
    let recycle_sid = components
        .first()
        .filter(|value| looks_like_sid(value))
        .cloned();
    let lower_name = file_name.to_ascii_lowercase();

    if lower_name == "desktop.ini" {
        return RecycleBinClassification {
            recycle_sid,
            artifact_kind: RecycleBinArtifactKind::DesktopIni,
            pair_id: None,
            extension,
        };
    }
    if lower_name == "info2" {
        return RecycleBinClassification {
            recycle_sid,
            artifact_kind: RecycleBinArtifactKind::Info2,
            pair_id: None,
            extension: None,
        };
    }
    if let Some(pair) = modern_pair_from_name(&file_name) {
        return RecycleBinClassification {
            recycle_sid,
            artifact_kind: if file_name
                .chars()
                .nth(1)
                .is_some_and(|value| value.eq_ignore_ascii_case(&'I'))
            {
                RecycleBinArtifactKind::MetadataI
            } else {
                RecycleBinArtifactKind::PayloadR
            },
            pair_id: Some(pair.pair_id),
            extension: pair.extension,
        };
    }

    let ancestor_pair = relative_path
        .parent()
        .and_then(ancestor_recycled_directory_pair_id);
    if ancestor_pair.is_some() {
        return RecycleBinClassification {
            recycle_sid,
            artifact_kind: RecycleBinArtifactKind::RecycledDirectoryMember,
            pair_id: ancestor_pair,
            extension,
        };
    }

    let artifact_kind = if components.len() == 1 {
        RecycleBinArtifactKind::RootFile
    } else if matches!(root_kind, RecycleBinRootKind::Legacy) {
        RecycleBinArtifactKind::LegacyRenamed
    } else {
        RecycleBinArtifactKind::Other
    };

    RecycleBinClassification {
        recycle_sid,
        artifact_kind,
        pair_id: None,
        extension,
    }
}

fn modern_pair_from_name(file_name: &str) -> Option<PairIdentity> {
    let mut characters = file_name.chars();
    if characters.next()? != '$' {
        return None;
    }
    let selector = characters.next()?;
    if !selector.eq_ignore_ascii_case(&'I') && !selector.eq_ignore_ascii_case(&'R') {
        return None;
    }

    let remainder = characters.collect::<String>();
    if remainder.trim().is_empty() {
        return None;
    }

    let remainder_path = Path::new(&remainder);
    let pair_id = remainder_path
        .file_stem()
        .map(|value| value.to_string_lossy().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| remainder.clone());
    let extension = remainder_path
        .extension()
        .map(|value| format!(".{}", value.to_string_lossy()));
    Some(PairIdentity { pair_id, extension })
}

fn ancestor_recycled_directory_pair_id(path: &Path) -> Option<String> {
    path.components().rev().find_map(|component| {
        modern_pair_from_name(&component.as_os_str().to_string_lossy()).map(|pair| pair.pair_id)
    })
}

fn looks_like_sid(value: &str) -> bool {
    value.trim().to_ascii_uppercase().starts_with("S-")
}

fn file_extension_with_dot(file_name: &str) -> Option<String> {
    Path::new(file_name)
        .extension()
        .map(|value| format!(".{}", value.to_string_lossy()))
}

fn join_live_path(root: &str, relative_path: &Path) -> String {
    let relative = normalize_live_path_string(relative_path);
    if relative.is_empty() {
        root.to_string()
    } else {
        format!(r"{}\{}", root, relative)
    }
}

fn recycle_bin_source_roots(volume: &str) -> Vec<String> {
    vec![
        format!(r"{volume}\$Recycle.Bin"),
        format!(r"{volume}\Recycler"),
    ]
}

fn relative_output_path_string(output_root: &Path, path: &Path) -> String {
    match path.strip_prefix(output_root) {
        Ok(relative) => normalize_archive_path_string(relative),
        Err(_) => path.display().to_string(),
    }
}

fn materialize_output_path(output_root: &Path, stored_path: &str) -> PathBuf {
    let candidate = PathBuf::from(stored_path);
    if candidate.is_absolute() {
        candidate
    } else {
        output_root.join(stored_path.replace('/', "\\"))
    }
}

fn normalize_live_path_string(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("\\")
}

fn is_reparse_or_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| {
            metadata.file_type().is_symlink() || {
                #[cfg(target_os = "windows")]
                {
                    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                }
                #[cfg(not(target_os = "windows"))]
                {
                    false
                }
            }
        })
        .unwrap_or(false)
}

fn copy_recycle_bin_file(
    volume: &str,
    planned_file: &PlannedRecycleBinFile,
    destination_path: &Path,
) -> Result<RecycleBinCollectedFile> {
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "create Recycle Bin destination directory {}",
                parent.display()
            )
        })?;
    }

    let source_hash = sha256_file(&planned_file.source_path)
        .with_context(|| format!("hash source {}", planned_file.source_path.display()))?;
    fs::copy(&planned_file.source_path, destination_path).with_context(|| {
        format!(
            "copy Recycle Bin file {} -> {}",
            planned_file.source_path.display(),
            destination_path.display()
        )
    })?;
    let destination_hash = sha256_file(destination_path)
        .with_context(|| format!("hash destination {}", destination_path.display()))?;
    if source_hash != destination_hash {
        bail!(
            "source/destination SHA-256 mismatch source={} destination={}",
            source_hash,
            destination_hash
        );
    }

    let metadata = fs::metadata(&planned_file.source_path)
        .with_context(|| format!("metadata {}", planned_file.source_path.display()))?;
    let collection_time_utc = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
    Ok(RecycleBinCollectedFile {
        archive_path: normalize_archive_path_string(&planned_file.archive_path),
        source_volume: usn_journal::normalize_volume(volume)?,
        source_path: planned_file.live_path.clone(),
        destination_path: normalize_archive_path_string(&planned_file.archive_path),
        vss_path: planned_file.source_path.display().to_string(),
        root_kind: planned_file.root_kind,
        recycle_sid: planned_file.recycle_sid.clone(),
        artifact_kind: planned_file.artifact_kind,
        pair_id: planned_file.pair_id.clone(),
        extension: planned_file.extension.clone(),
        is_directory: false,
        file_size: metadata.len(),
        created_time: system_time_utc(metadata.created().ok()),
        modified_time: system_time_utc(metadata.modified().ok()),
        accessed_time: system_time_utc(metadata.accessed().ok()),
        source_file_attributes: source_file_attributes(&metadata),
        source_sha256: source_hash,
        sha256: destination_hash,
        collection_time_utc,
        copy_status: "success".to_string(),
    })
}

#[cfg(target_os = "windows")]
fn source_file_attributes(metadata: &fs::Metadata) -> Option<u32> {
    Some(metadata.file_attributes())
}

#[cfg(not(target_os = "windows"))]
fn source_file_attributes(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

fn write_artifact_manifest(path: &Path, file_records: &[RecycleBinCollectedFile]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "create Recycle Bin artifact manifest directory {}",
                parent.display()
            )
        })?;
    }

    let file = File::create(path)
        .with_context(|| format!("create Recycle Bin artifact manifest {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    for record in file_records {
        serde_json::to_writer(&mut writer, &RecycleBinArtifactManifestRecord::from(record))?;
        writer.write_all(b"\n")?;
    }
    writer
        .flush()
        .context("flush Recycle Bin artifact manifest")
}

fn write_manifest(path: &Path, manifest: &RecycleBinCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create manifest directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(manifest)?;
    fs::write(path, bytes).with_context(|| format!("write manifest {}", path.display()))
}

fn write_collection_log(path: &Path, manifest: &RecycleBinCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create collection log directory {}", parent.display()))?;
    }

    let file =
        File::create(path).with_context(|| format!("create Recycle Bin log {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "recycle_bin collection volume={}", manifest.volume)?;
    writeln!(writer, "source_root={}", manifest.source_root)?;
    writeln!(writer, "roots_present={}", manifest.total_roots_present)?;
    writeln!(
        writer,
        "artifact_manifest={}",
        manifest.artifact_manifest_path
    )?;
    writeln!(
        writer,
        "found={} copied={} failed={}",
        manifest.total_files_found, manifest.total_files_copied, manifest.total_files_failed
    )?;
    for entry in &manifest.files {
        writeln!(
            writer,
            "copied {} size={} sha256={} kind={:?} root={:?}",
            entry.archive_path, entry.file_size, entry.sha256, entry.artifact_kind, entry.root_kind
        )?;
    }
    for failure in &manifest.failures {
        writeln!(
            writer,
            "failed {} operation={} error={}",
            failure.archive_path, failure.operation, failure.error
        )?;
    }
    writer.flush().context("flush Recycle Bin collection log")
}

fn mark_shadow_deleted(manifest_path: &Path) -> Result<()> {
    let bytes = fs::read(manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let mut manifest: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode manifest {}", manifest_path.display()))?;
    if let Some(shadow_copy) = manifest
        .get_mut("shadow_copy")
        .and_then(serde_json::Value::as_object_mut)
    {
        shadow_copy.insert("deleted".to_string(), serde_json::Value::Bool(true));
    }
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    fs::write(manifest_path, bytes)
        .with_context(|| format!("write manifest {}", manifest_path.display()))
}

fn volume_archive_root(volume: &str) -> Result<PathBuf> {
    let normalized = usn_journal::normalize_volume(volume)?;
    Ok(PathBuf::from(normalized.trim_end_matches(':')))
}

fn progress_fraction(index: usize, total: usize) -> f32 {
    if total == 0 {
        1.0
    } else {
        index as f32 / total as f32
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn system_time_utc(time: Option<std::time::SystemTime>) -> Option<String> {
    time.map(|value| DateTime::<Utc>::from(value).to_rfc3339_opts(SecondsFormat::Nanos, true))
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(target_os = "windows")]
fn is_process_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(target_os = "windows"))]
fn is_process_elevated() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn enable_privilege(privilege_name: &str) -> Result<()> {
    use windows::Win32::Foundation::{CloseHandle, GetLastError, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::PCWSTR;

    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .with_context(|| format!("open process token for {privilege_name}"))?;
        let mut luid = LUID::default();
        let privilege_wide = privilege_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();
        let lookup_result = LookupPrivilegeValueW(None, PCWSTR(privilege_wide.as_ptr()), &mut luid);
        if let Err(error) = lookup_result {
            let _ = CloseHandle(token);
            return Err(error).with_context(|| format!("lookup privilege {privilege_name}"));
        }
        let mut privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let adjust_result =
            AdjustTokenPrivileges(token, false, Some(&mut privileges), 0, None, None);
        let _ = CloseHandle(token);
        adjust_result.with_context(|| format!("enable privilege {privilege_name}"))?;
        let last_error = GetLastError();
        if last_error.0 != 0 {
            bail!(
                "AdjustTokenPrivileges for {} completed with error code {}",
                privilege_name,
                last_error.0
            );
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
fn enable_privilege(privilege_name: &str) -> Result<()> {
    bail!("{privilege_name} is only available on Windows")
}

#[cfg(target_os = "windows")]
fn relaunch_elevated(request: &RecycleBinCollectRequest) -> Result<()> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWDEFAULT;
    use windows::core::{PCWSTR, w};

    let current_exe = std::env::current_exe().context("resolve current executable path")?;
    let current_dir = std::env::current_dir().context("resolve current working directory")?;
    let parameters = build_relaunch_parameters(request);
    let current_exe_wide = encode_wide_os(current_exe.as_os_str());
    let current_dir_wide = encode_wide_os(current_dir.as_os_str());
    let parameters_wide = encode_wide(&parameters);

    let mut execute = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(current_exe_wide.as_ptr()),
        lpParameters: PCWSTR(parameters_wide.as_ptr()),
        lpDirectory: PCWSTR(current_dir_wide.as_ptr()),
        nShow: SW_SHOWDEFAULT.0,
        ..Default::default()
    };

    unsafe { ShellExecuteExW(&mut execute) }
        .context("launch elevated Recycle Bin collector via UAC")?;
    if execute.hProcess.is_invalid() {
        bail!("UAC launch did not return a process handle to wait on");
    }

    unsafe {
        WaitForSingleObject(execute.hProcess, INFINITE);
    }
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(execute.hProcess, &mut exit_code) }
        .context("read elevated Recycle Bin collector exit code")?;
    let _ = unsafe { CloseHandle(execute.hProcess) };
    if exit_code != 0 {
        bail!("elevated Recycle Bin collector exited with status {exit_code}");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn relaunch_elevated(_request: &RecycleBinCollectRequest) -> Result<()> {
    bail!("Recycle Bin elevation relaunch is only available on Windows")
}

fn build_relaunch_parameters(request: &RecycleBinCollectRequest) -> String {
    let mut values = vec![
        "collect-recycle-bin".to_string(),
        "--volume".to_string(),
        request.volume.clone(),
        "--out-dir".to_string(),
        request.out_dir.display().to_string(),
    ];

    if let Some(manifest) = request.manifest.as_ref() {
        values.push("--manifest".to_string());
        values.push(manifest.display().to_string());
    }
    if let Some(artifact_manifest) = request.artifact_manifest.as_ref() {
        values.push("--artifact-manifest".to_string());
        values.push(artifact_manifest.display().to_string());
    }
    if let Some(collection_log) = request.collection_log.as_ref() {
        values.push("--collection-log".to_string());
        values.push(collection_log.display().to_string());
    }
    if let Some(diagnostic_log) = request.diagnostic_log.as_ref() {
        values.push("--diagnostic-log".to_string());
        values.push(diagnostic_log.display().to_string());
    }

    values
        .into_iter()
        .map(|value| quote_windows_argument(&value))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_windows_argument(value: &str) -> String {
    if !value.is_empty() && !value.contains([' ', '\t', '"']) {
        return value.to_string();
    }

    let mut output = String::from("\"");
    let mut backslash_count = 0usize;
    for character in value.chars() {
        match character {
            '\\' => backslash_count += 1,
            '"' => {
                output.push_str(&"\\".repeat((backslash_count * 2) + 1));
                output.push('"');
                backslash_count = 0;
            }
            _ => {
                if backslash_count > 0 {
                    output.push_str(&"\\".repeat(backslash_count));
                    backslash_count = 0;
                }
                output.push(character);
            }
        }
    }

    if backslash_count > 0 {
        output.push_str(&"\\".repeat(backslash_count * 2));
    }
    output.push('"');
    output
}

fn encode_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn encode_wide_os(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn normalize_archive_path_string(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use anyhow::Result;
    use tempfile::tempdir;

    use super::{
        RecycleBinArtifactKind, RecycleBinRootKind, classify_recycle_bin_item,
        default_artifact_manifest_path, default_collection_log_path, default_manifest_path,
        plan_recycle_bin_files,
    };

    #[test]
    fn default_recycle_bin_metadata_paths_live_under_expected_roots() -> Result<()> {
        let root = PathBuf::from(r"C:\evidence");
        assert_eq!(
            default_manifest_path(&root, "c:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_recycle_bin")
                .join("manifest.json")
        );
        assert_eq!(
            default_collection_log_path(&root, r"\\?\C:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_recycle_bin")
                .join("collection.log")
        );
        assert_eq!(
            default_artifact_manifest_path(&root, "c:")?,
            root.join("C").join("recycle_bin_manifest.jsonl")
        );
        Ok(())
    }

    #[test]
    fn plan_recycle_bin_files_collects_modern_and_legacy_roots() -> Result<()> {
        let temp = tempdir()?;
        let source_root = temp.path().join("shadow");
        let modern_root = source_root.join("$Recycle.Bin");
        let modern_sid = modern_root.join("S-1-5-21-111-222-333-1001");
        let recycled_dir = modern_sid.join("$RXYZ789");
        let legacy_root = source_root
            .join("Recycler")
            .join("S-1-5-21-444-555-666-1002");

        fs::create_dir_all(&recycled_dir)?;
        fs::create_dir_all(&legacy_root)?;
        fs::write(modern_root.join("suspicious_root_file.exe"), b"root")?;
        fs::write(modern_root.join("desktop.ini"), b"desktop")?;
        fs::write(modern_sid.join("$IABC123.docx"), b"metadata")?;
        fs::write(modern_sid.join("$RABC123.docx"), b"payload")?;
        fs::write(recycled_dir.join("nested-file.txt"), b"nested")?;
        fs::write(legacy_root.join("INFO2"), b"\x05\0\0\0stub-info2")?;
        fs::write(legacy_root.join("DC1.txt"), b"legacy")?;

        let plan = plan_recycle_bin_files("c:", &source_root)?;

        assert_eq!(plan.roots_present, 2);
        assert_eq!(plan.files.len(), 7);
        assert!(plan.files.iter().any(|file| {
            file.root_kind == RecycleBinRootKind::Modern
                && file.artifact_kind == RecycleBinArtifactKind::RootFile
                && file.archive_path
                    == PathBuf::from("C")
                        .join("$Recycle.Bin")
                        .join("suspicious_root_file.exe")
        }));
        assert!(plan.files.iter().any(|file| {
            file.artifact_kind == RecycleBinArtifactKind::MetadataI
                && file.recycle_sid.as_deref() == Some("S-1-5-21-111-222-333-1001")
                && file.pair_id.as_deref() == Some("ABC123")
                && file.extension.as_deref() == Some(".docx")
        }));
        assert!(plan.files.iter().any(|file| {
            file.artifact_kind == RecycleBinArtifactKind::RecycledDirectoryMember
                && file.pair_id.as_deref() == Some("XYZ789")
                && file.archive_path
                    == PathBuf::from("C")
                        .join("$Recycle.Bin")
                        .join("S-1-5-21-111-222-333-1001")
                        .join("$RXYZ789")
                        .join("nested-file.txt")
        }));
        assert!(plan.files.iter().any(|file| {
            file.root_kind == RecycleBinRootKind::Legacy
                && file.artifact_kind == RecycleBinArtifactKind::Info2
                && file.archive_path
                    == PathBuf::from("C")
                        .join("Recycler")
                        .join("S-1-5-21-444-555-666-1002")
                        .join("INFO2")
        }));
        assert!(plan.files.iter().any(|file| {
            file.root_kind == RecycleBinRootKind::Legacy
                && file.artifact_kind == RecycleBinArtifactKind::LegacyRenamed
                && file.archive_path
                    == PathBuf::from("C")
                        .join("Recycler")
                        .join("S-1-5-21-444-555-666-1002")
                        .join("DC1.txt")
        }));
        Ok(())
    }

    #[test]
    fn classify_recycle_bin_item_tracks_pairing_and_root_files() {
        let root = classify_recycle_bin_item(
            RecycleBinRootKind::Modern,
            Path::new("suspicious_root_file.exe"),
            std::ffi::OsStr::new("suspicious_root_file.exe"),
        );
        assert_eq!(root.artifact_kind, RecycleBinArtifactKind::RootFile);
        assert_eq!(root.extension.as_deref(), Some(".exe"));

        let nested = classify_recycle_bin_item(
            RecycleBinRootKind::Modern,
            Path::new(r"S-1-5-21-100\$RXYZ789\nested-file.txt"),
            std::ffi::OsStr::new("nested-file.txt"),
        );
        assert_eq!(
            nested.artifact_kind,
            RecycleBinArtifactKind::RecycledDirectoryMember
        );
        assert_eq!(nested.recycle_sid.as_deref(), Some("S-1-5-21-100"));
        assert_eq!(nested.pair_id.as_deref(), Some("XYZ789"));
        assert_eq!(nested.extension.as_deref(), Some(".txt"));
    }
}
