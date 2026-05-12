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

const POWERSHELL_ACTIVITY_COLLECTION_SCHEMA: &str = "windows_powershell_activity_collection_v1";
const POWERSHELL_ACTIVITY_COLLECTOR_NAME: &str = "windows_powershell_activity";
const LOW_VALUE_PROFILE_NAMES: &[&str] = &[
    "all users",
    "default",
    "default user",
    "defaultapppool",
    "defaultuser0",
    "public",
];
const MAX_RECURSIVE_FILE_SIZE_BYTES: u64 = 20 * 1024 * 1024;
const ALLOWED_RECURSIVE_EXTENSIONS: &[&str] = &[
    ".ps1", ".psm1", ".psd1", ".ps1xml", ".clixml", ".txt", ".json", ".xml", ".config",
];
const FIXED_USER_FILE_TEMPLATES: &[(&str, PowerShellArtifactKind)] = &[
    (
        r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        PowerShellArtifactKind::PsReadLineHistory,
    ),
    (
        r"AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt",
        PowerShellArtifactKind::PsReadLineHistory,
    ),
    (
        r"Documents\WindowsPowerShell\profile.ps1",
        PowerShellArtifactKind::ProfileScript,
    ),
    (
        r"Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
        PowerShellArtifactKind::ProfileScript,
    ),
    (
        r"Documents\WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1",
        PowerShellArtifactKind::ProfileScript,
    ),
    (
        r"Documents\PowerShell\profile.ps1",
        PowerShellArtifactKind::ProfileScript,
    ),
    (
        r"Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
        PowerShellArtifactKind::ProfileScript,
    ),
];
const RECURSIVE_ROOT_TEMPLATES: &[(&str, PowerShellDirectoryKind)] = &[
    (
        r"Documents\WindowsPowerShell\Modules",
        PowerShellDirectoryKind::ModulesRoot,
    ),
    (
        r"Documents\PowerShell\Modules",
        PowerShellDirectoryKind::ModulesRoot,
    ),
    (
        r"AppData\Local\Microsoft\Windows\PowerShell",
        PowerShellDirectoryKind::PowerShellDataRoot,
    ),
    (
        r"AppData\Roaming\Microsoft\Windows\PowerShell",
        PowerShellDirectoryKind::PowerShellDataRoot,
    ),
    (
        r"AppData\Local\Microsoft\PowerShell",
        PowerShellDirectoryKind::PowerShellDataRoot,
    ),
    (
        r"AppData\Roaming\Microsoft\PowerShell",
        PowerShellDirectoryKind::PowerShellDataRoot,
    ),
    (
        r"Documents\WindowsPowerShell\Transcripts",
        PowerShellDirectoryKind::TranscriptRoot,
    ),
    (
        r"Documents\PowerShell\Transcripts",
        PowerShellDirectoryKind::TranscriptRoot,
    ),
];
#[cfg(target_os = "windows")]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

#[derive(Debug, Clone, Args)]
pub struct PowerShellActivityCollectCli {
    #[arg(long, help = "NTFS volume, for example C:")]
    pub volume: String,

    #[arg(
        long = "out-dir",
        help = "Output root directory for collected PowerShell activity artifacts"
    )]
    pub out_dir: PathBuf,

    #[arg(
        long,
        help = "Optional collection manifest path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_powershell_activity/manifest.json"
    )]
    pub manifest: Option<PathBuf>,

    #[arg(
        long = "collection-log",
        help = "Optional collection log path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_powershell_activity/collection.log"
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
pub struct PowerShellActivityCollectRequest {
    pub volume: String,
    pub out_dir: PathBuf,
    pub manifest: Option<PathBuf>,
    pub collection_log: Option<PathBuf>,
    pub diagnostic_log: Option<PathBuf>,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct PowerShellActivityCollectSummary {
    pub volume: String,
    pub output_root: PathBuf,
    pub manifest_path: PathBuf,
    pub collection_log_path: PathBuf,
    pub staged_paths: Vec<PathBuf>,
    pub file_records: Vec<PowerShellActivityCollectedFile>,
    pub directory_records: Vec<PowerShellActivityCollectedDirectory>,
    pub skipped_files: Vec<PowerShellActivitySkippedFile>,
    pub failures: Vec<PowerShellActivityCollectionFailure>,
}

#[derive(Debug, Clone)]
pub struct PowerShellActivityProgress {
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
pub enum PowerShellArtifactKind {
    PsReadLineHistory,
    ProfileScript,
    Transcript,
    ModuleSupportFile,
    PowerShellDataFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerShellDirectoryKind {
    ModulesRoot,
    PowerShellDataRoot,
    TranscriptRoot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShellActivityCollectedFile {
    pub archive_path: String,
    pub live_path: String,
    pub vss_path: String,
    pub profile_username: String,
    pub artifact_kind: PowerShellArtifactKind,
    pub file_name: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessed_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file_attributes: Option<u32>,
    pub source_sha256: String,
    pub sha256: String,
    pub copy_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShellActivityCollectedDirectory {
    pub archive_path: String,
    pub live_path: String,
    pub vss_path: String,
    pub profile_username: String,
    pub directory_kind: PowerShellDirectoryKind,
    pub directory_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessed_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file_attributes: Option<u32>,
    pub record_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShellActivitySkippedFile {
    pub profile_username: String,
    pub live_path: String,
    pub vss_path: String,
    pub archive_path: String,
    pub size: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShellActivityCollectionFailure {
    pub profile_username: String,
    pub live_path: String,
    pub vss_path: String,
    pub archive_path: String,
    pub operation: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PowerShellActivityCollectionManifest {
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
    source_globs: Vec<String>,
    allowed_extensions: Vec<String>,
    max_file_size_bytes: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    privileges_enabled: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shadow_copy: Option<ShadowCopyMetadata>,
    total_profiles_scanned: usize,
    total_profiles_skipped: usize,
    total_directories_recorded: usize,
    total_files_found: usize,
    total_files_copied: usize,
    total_files_skipped: usize,
    total_files_failed: usize,
    files: Vec<PowerShellActivityCollectedFile>,
    directories: Vec<PowerShellActivityCollectedDirectory>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    skipped_files: Vec<PowerShellActivitySkippedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    failures: Vec<PowerShellActivityCollectionFailure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct PlannedPowerShellFile {
    source_path: PathBuf,
    live_path: String,
    archive_path: PathBuf,
    profile_username: String,
    artifact_kind: PowerShellArtifactKind,
    file_name: String,
}

struct PowerShellActivityPlan {
    files: Vec<PlannedPowerShellFile>,
    directory_records: Vec<PowerShellActivityCollectedDirectory>,
    skipped_files: Vec<PowerShellActivitySkippedFile>,
    warnings: Vec<String>,
    profiles_scanned: usize,
    profiles_skipped: usize,
}

pub fn run(args: &PowerShellActivityCollectCli) -> Result<()> {
    let summary = collect(&PowerShellActivityCollectRequest {
        volume: args.volume.clone(),
        out_dir: args.out_dir.clone(),
        manifest: args.manifest.clone(),
        collection_log: args.collection_log.clone(),
        diagnostic_log: args.diagnostic_log.clone(),
        elevate: args.elevate,
    })?;
    println!(
        "Collected {} PowerShell activity files.",
        summary.file_records.len()
    );
    println!(
        "Recorded {} PowerShell activity directories.",
        summary.directory_records.len()
    );
    println!(
        "Skipped {} PowerShell activity files.",
        summary.skipped_files.len()
    );
    println!(
        "Failed {} PowerShell activity files.",
        summary.failures.len()
    );
    println!("Manifest: {}", summary.manifest_path.display());
    println!("Collection log: {}", summary.collection_log_path.display());
    Ok(())
}

pub fn collect(
    request: &PowerShellActivityCollectRequest,
) -> Result<PowerShellActivityCollectSummary> {
    let mut reporter = |_| {};
    collect_with_progress(request, &mut reporter)
}

pub fn collect_with_progress(
    request: &PowerShellActivityCollectRequest,
    reporter: &mut dyn FnMut(PowerShellActivityProgress),
) -> Result<PowerShellActivityCollectSummary> {
    validate_request(request)?;
    let volume = usn_journal::normalize_volume(&request.volume)?;
    let manifest_path = request
        .manifest
        .clone()
        .unwrap_or(default_manifest_path(&request.out_dir, &volume)?);
    let collection_log_path = request
        .collection_log
        .clone()
        .unwrap_or(default_collection_log_path(&request.out_dir, &volume)?);

    if request.elevate && !is_process_elevated() {
        reporter(PowerShellActivityProgress {
            progress_value: 0.03,
            detail: "Waiting for elevation approval.".to_string(),
            progress_text: "UAC".to_string(),
        });
        relaunch_elevated(request)?;
        return load_existing_summary(
            &volume,
            &request.out_dir,
            &manifest_path,
            &collection_log_path,
        );
    }

    let shadow_copy = vss::create_shadow_copy(&request.volume)?;
    let result = collect_from_shadow_copy(request, &shadow_copy, false, reporter);
    let delete_result = vss::delete_shadow_copy(&shadow_copy.id)
        .with_context(|| format!("delete PowerShell activity shadow copy {}", shadow_copy.id));
    match (result, delete_result) {
        (Ok(summary), Ok(())) => {
            mark_shadow_deleted(&summary.manifest_path)?;
            Ok(summary)
        }
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(delete_error)) => Err(error.context(format!(
            "also failed to delete PowerShell activity shadow copy {}: {delete_error:#}",
            shadow_copy.id
        ))),
    }
}

pub fn collect_with_progress_using_shadow_copy(
    request: &PowerShellActivityCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    reporter: &mut dyn FnMut(PowerShellActivityProgress),
) -> Result<PowerShellActivityCollectSummary> {
    validate_request(request)?;
    collect_from_shadow_copy(request, shadow_copy, true, reporter)
}

pub fn default_manifest_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_manifest_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_POWERSHELL_ACTIVITY_COLLECTOR,
    )
}

pub fn default_collection_log_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_log_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_POWERSHELL_ACTIVITY_COLLECTOR,
    )
}

pub fn default_diagnostic_log_path(_output_root: &Path) -> PathBuf {
    runtime_support::technical_log_path()
}

fn validate_request(request: &PowerShellActivityCollectRequest) -> Result<()> {
    let _ = usn_journal::normalize_volume(&request.volume)?;
    if request.out_dir.as_os_str().is_empty() {
        bail!("--out-dir must not be empty");
    }
    Ok(())
}

fn collect_from_shadow_copy(
    request: &PowerShellActivityCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    shared_shadow_copy: bool,
    reporter: &mut dyn FnMut(PowerShellActivityProgress),
) -> Result<PowerShellActivityCollectSummary> {
    let volume = usn_journal::normalize_volume(&request.volume)?;
    let manifest_path = request
        .manifest
        .clone()
        .unwrap_or(default_manifest_path(&request.out_dir, &volume)?);
    let collection_log_path = request
        .collection_log
        .clone()
        .unwrap_or(default_collection_log_path(&request.out_dir, &volume)?);

    fs::create_dir_all(&request.out_dir)
        .with_context(|| format!("create output root {}", request.out_dir.display()))?;
    reporter(PowerShellActivityProgress {
        progress_value: 0.05,
        detail: format!("Enumerating PowerShell activity artifacts on {volume}."),
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

    let planned = plan_powershell_activity_files(&volume, &source_root)?;
    warnings.extend(planned.warnings);

    let total = planned.files.len();
    let directory_records = planned.directory_records;
    let skipped_files = planned.skipped_files;
    let profiles_scanned = planned.profiles_scanned;
    let profiles_skipped = planned.profiles_skipped;
    let mut staged_paths = Vec::new();
    let mut file_records = Vec::new();
    let mut failures = Vec::new();

    for (index, planned_file) in planned.files.into_iter().enumerate() {
        let archive_name = normalize_archive_path_string(&planned_file.archive_path);
        let destination_path = request.out_dir.join(&planned_file.archive_path);
        reporter(PowerShellActivityProgress {
            progress_value: 0.08 + (0.82 * progress_fraction(index, total)),
            detail: format!("Copying {archive_name}"),
            progress_text: format!("{index} / {total} files"),
        });
        match copy_powershell_activity_file(&planned_file, &destination_path) {
            Ok(record) => {
                staged_paths.push(destination_path);
                file_records.push(record);
            }
            Err(error) => failures.push(PowerShellActivityCollectionFailure {
                profile_username: planned_file.profile_username,
                live_path: planned_file.live_path,
                vss_path: planned_file.source_path.display().to_string(),
                archive_path: archive_name,
                operation: "copy_hash_verify".to_string(),
                error: error.to_string(),
            }),
        }
    }

    reporter(PowerShellActivityProgress {
        progress_value: 0.94,
        detail: "Writing PowerShell activity manifest and collection log.".to_string(),
        progress_text: "Manifest".to_string(),
    });
    let end_time = Utc::now();
    let manifest = PowerShellActivityCollectionManifest {
        metadata_schema: POWERSHELL_ACTIVITY_COLLECTION_SCHEMA.to_string(),
        artifact_type: "windows_powershell_activity_collection".to_string(),
        artifact_name: "Windows PowerShell Activity".to_string(),
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
            name: POWERSHELL_ACTIVITY_COLLECTOR_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            language: "rust".to_string(),
        },
        transaction_safe: true,
        source_root: source_root.display().to_string(),
        source_globs: powershell_activity_source_globs(&volume),
        allowed_extensions: ALLOWED_RECURSIVE_EXTENSIONS
            .iter()
            .map(|value| value.to_string())
            .collect(),
        max_file_size_bytes: MAX_RECURSIVE_FILE_SIZE_BYTES,
        privileges_enabled,
        shadow_copy: Some(ShadowCopyMetadata {
            created: !shared_shadow_copy,
            deleted: false,
            shared: shared_shadow_copy,
            id: shadow_copy.id.clone(),
            device_object: shadow_copy.device_object.clone(),
            context: shadow_copy.context.clone(),
        }),
        total_profiles_scanned: profiles_scanned,
        total_profiles_skipped: profiles_skipped,
        total_directories_recorded: directory_records.len(),
        total_files_found: total,
        total_files_copied: file_records.len(),
        total_files_skipped: skipped_files.len(),
        total_files_failed: failures.len(),
        files: file_records.clone(),
        directories: directory_records.clone(),
        skipped_files: skipped_files.clone(),
        failures: failures.clone(),
        warnings,
    };

    write_manifest(&manifest_path, &manifest)?;
    write_collection_log(&collection_log_path, &manifest)?;
    staged_paths.push(manifest_path.clone());
    staged_paths.push(collection_log_path.clone());

    reporter(PowerShellActivityProgress {
        progress_value: 1.0,
        detail: format!(
            "Copied {} of {} PowerShell activity files from {volume}.",
            file_records.len(),
            total
        ),
        progress_text: format!(
            "{} copied, {} skipped, {} failed",
            file_records.len(),
            skipped_files.len(),
            failures.len()
        ),
    });

    Ok(PowerShellActivityCollectSummary {
        volume,
        output_root: request.out_dir.clone(),
        manifest_path,
        collection_log_path,
        staged_paths,
        file_records,
        directory_records,
        skipped_files,
        failures,
    })
}

fn load_existing_summary(
    volume: &str,
    output_root: &Path,
    manifest_path: &Path,
    collection_log_path: &Path,
) -> Result<PowerShellActivityCollectSummary> {
    let bytes = fs::read(manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let manifest: PowerShellActivityCollectionManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode manifest {}", manifest_path.display()))?;
    let mut staged_paths = manifest
        .files
        .iter()
        .map(|record| materialize_output_path(output_root, &record.archive_path))
        .collect::<Vec<_>>();
    staged_paths.push(manifest_path.to_path_buf());
    staged_paths.push(collection_log_path.to_path_buf());
    Ok(PowerShellActivityCollectSummary {
        volume: volume.to_string(),
        output_root: output_root.to_path_buf(),
        manifest_path: manifest_path.to_path_buf(),
        collection_log_path: collection_log_path.to_path_buf(),
        staged_paths,
        file_records: manifest.files,
        directory_records: manifest.directories,
        skipped_files: manifest.skipped_files,
        failures: manifest.failures,
    })
}

fn plan_powershell_activity_files(
    volume: &str,
    source_root: &Path,
) -> Result<PowerShellActivityPlan> {
    let normalized_volume = usn_journal::normalize_volume(volume)?;
    let archive_root = volume_archive_root(&normalized_volume)?;
    let users_root = source_root.join("Users");
    let mut files = Vec::new();
    let mut directory_records = Vec::new();
    let mut skipped_files = Vec::new();
    let mut warnings = Vec::new();
    let mut file_archive_paths = BTreeSet::new();
    let mut directory_archive_paths = BTreeSet::new();
    let mut profiles_scanned = 0usize;
    let mut profiles_skipped = 0usize;

    if users_root.exists() {
        for entry in fs::read_dir(&users_root)
            .with_context(|| format!("read users directory {}", users_root.display()))?
        {
            let entry = entry.with_context(|| format!("read entry in {}", users_root.display()))?;
            let profile_root = entry.path();
            if !profile_root.is_dir() {
                continue;
            }

            profiles_scanned += 1;
            let profile_name = entry.file_name().to_string_lossy().to_string();
            let live_profile_root = format!(r"{}\Users\{}", normalized_volume, profile_name);
            let archive_profile_root = archive_root.join("Users").join(&profile_name);

            if is_low_value_profile_name(&profile_name) {
                profiles_skipped += 1;
                continue;
            }
            if is_reparse_or_symlink(&profile_root) {
                profiles_skipped += 1;
                warnings.push(format!(
                    "skipped reparse/symlink profile root: {live_profile_root}"
                ));
                continue;
            }

            add_fixed_user_files(
                &profile_root,
                &archive_profile_root,
                &live_profile_root,
                &profile_name,
                &mut files,
                &mut file_archive_paths,
                &mut warnings,
            );
            add_root_transcript_files(
                &profile_root.join("Documents"),
                &archive_profile_root.join("Documents"),
                &format!(r"{}\Documents", live_profile_root),
                &profile_name,
                &mut files,
                &mut file_archive_paths,
                &mut skipped_files,
                &mut warnings,
            )?;

            for (relative_root, directory_kind) in RECURSIVE_ROOT_TEMPLATES {
                let relative_root_path = PathBuf::from(relative_root);
                let source_dir = profile_root.join(&relative_root_path);
                let archive_dir = archive_profile_root.join(&relative_root_path);
                let live_dir = join_live_path(&live_profile_root, &relative_root_path);
                collect_recursive_root(
                    &source_dir,
                    &source_dir,
                    &archive_dir,
                    &live_dir,
                    &profile_name,
                    *directory_kind,
                    &mut files,
                    &mut directory_records,
                    &mut skipped_files,
                    &mut file_archive_paths,
                    &mut directory_archive_paths,
                    &mut warnings,
                )?;
            }
        }
    } else {
        warnings.push(format!(
            "users directory was not present in snapshot: {}",
            users_root.display()
        ));
    }

    files.sort_by_key(|file| file.archive_path.display().to_string().to_ascii_lowercase());
    directory_records.sort_by_key(|record| record.archive_path.to_ascii_lowercase());
    skipped_files.sort_by_key(|record| record.archive_path.to_ascii_lowercase());

    Ok(PowerShellActivityPlan {
        files,
        directory_records,
        skipped_files,
        warnings,
        profiles_scanned,
        profiles_skipped,
    })
}

fn add_fixed_user_files(
    profile_root: &Path,
    archive_profile_root: &Path,
    live_profile_root: &str,
    profile_username: &str,
    files: &mut Vec<PlannedPowerShellFile>,
    file_archive_paths: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    for (relative_path, artifact_kind) in FIXED_USER_FILE_TEMPLATES {
        let relative_path = PathBuf::from(relative_path);
        let source_path = profile_root.join(&relative_path);
        if !source_path.exists() {
            continue;
        }
        let live_path = join_live_path(live_profile_root, &relative_path);
        if !source_path.is_file() {
            warnings.push(format!("PowerShell artifact was not a file: {live_path}"));
            continue;
        }
        if is_reparse_or_symlink(&source_path) {
            warnings.push(format!(
                "skipped reparse/symlink PowerShell artifact: {live_path}"
            ));
            continue;
        }
        add_planned_file(
            &source_path,
            &live_path,
            &archive_profile_root.join(&relative_path),
            profile_username,
            *artifact_kind,
            files,
            file_archive_paths,
            warnings,
        );
    }
}

fn add_root_transcript_files(
    documents_root: &Path,
    archive_documents_root: &Path,
    live_documents_root: &str,
    profile_username: &str,
    files: &mut Vec<PlannedPowerShellFile>,
    file_archive_paths: &mut BTreeSet<String>,
    skipped_files: &mut Vec<PowerShellActivitySkippedFile>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    if !documents_root.exists() {
        return Ok(());
    }
    if !documents_root.is_dir() {
        warnings.push(format!(
            "Documents root was not a directory: {live_documents_root}"
        ));
        return Ok(());
    }
    if is_reparse_or_symlink(documents_root) {
        warnings.push(format!(
            "skipped reparse/symlink Documents root: {live_documents_root}"
        ));
        return Ok(());
    }

    let entries = match fs::read_dir(documents_root) {
        Ok(entries) => entries,
        Err(error) => {
            warnings.push(format!(
                "could not enumerate {live_documents_root}: {error}"
            ));
            return Ok(());
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(format!(
                    "could not read entry in {live_documents_root}: {error}"
                ));
                continue;
            }
        };
        let source_path = entry.path();
        if !source_path.is_file() {
            continue;
        }

        let file_name = entry.file_name().to_string_lossy().to_string();
        if !matches_root_transcript_file(&file_name) {
            continue;
        }

        let archive_path = archive_documents_root.join(&file_name);
        let live_path = format!(r"{}\{}", live_documents_root, file_name);
        if is_reparse_or_symlink(&source_path) {
            push_skipped_file(
                source_path.as_path(),
                &live_path,
                &archive_path,
                profile_username,
                "reparse_or_symlink",
                skipped_files,
            );
            continue;
        }

        let metadata = match fs::metadata(&source_path) {
            Ok(metadata) => metadata,
            Err(error) => {
                warnings.push(format!("could not read metadata for {live_path}: {error}"));
                continue;
            }
        };
        if metadata.len() > MAX_RECURSIVE_FILE_SIZE_BYTES {
            push_skipped_file(
                source_path.as_path(),
                &live_path,
                &archive_path,
                profile_username,
                &format!("size_limit_exceeded:{}", MAX_RECURSIVE_FILE_SIZE_BYTES),
                skipped_files,
            );
            continue;
        }

        add_planned_file(
            &source_path,
            &live_path,
            &archive_path,
            profile_username,
            PowerShellArtifactKind::Transcript,
            files,
            file_archive_paths,
            warnings,
        );
    }

    Ok(())
}

fn collect_recursive_root(
    root_dir: &Path,
    current_dir: &Path,
    archive_root: &Path,
    live_root: &str,
    profile_username: &str,
    directory_kind: PowerShellDirectoryKind,
    files: &mut Vec<PlannedPowerShellFile>,
    directory_records: &mut Vec<PowerShellActivityCollectedDirectory>,
    skipped_files: &mut Vec<PowerShellActivitySkippedFile>,
    file_archive_paths: &mut BTreeSet<String>,
    directory_archive_paths: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    if !root_dir.exists() {
        return Ok(());
    }
    if !root_dir.is_dir() {
        warnings.push(format!("PowerShell root was not a directory: {live_root}"));
        return Ok(());
    }
    if is_reparse_or_symlink(root_dir) {
        warnings.push(format!(
            "skipped reparse/symlink PowerShell root: {live_root}"
        ));
        return Ok(());
    }

    let relative_dir = current_dir.strip_prefix(root_dir).unwrap_or(Path::new(""));
    let archive_dir = if relative_dir.as_os_str().is_empty() {
        archive_root.to_path_buf()
    } else {
        archive_root.join(relative_dir)
    };
    let live_dir = join_live_path(live_root, relative_dir);
    add_directory_record(
        current_dir,
        &live_dir,
        &archive_dir,
        profile_username,
        directory_kind,
        directory_records,
        directory_archive_paths,
        warnings,
    );

    let entries = match fs::read_dir(current_dir) {
        Ok(entries) => entries,
        Err(error) => {
            warnings.push(format!("could not enumerate {live_dir}: {error}"));
            return Ok(());
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(format!("could not read entry in {live_dir}: {error}"));
                continue;
            }
        };
        let source_path = entry.path();

        if source_path.is_dir() {
            if is_reparse_or_symlink(&source_path) {
                warnings.push(format!(
                    "skipped reparse/symlink PowerShell directory: {}",
                    source_path.display()
                ));
                continue;
            }
            collect_recursive_root(
                root_dir,
                &source_path,
                archive_root,
                live_root,
                profile_username,
                directory_kind,
                files,
                directory_records,
                skipped_files,
                file_archive_paths,
                directory_archive_paths,
                warnings,
            )?;
            continue;
        }
        if !source_path.is_file() {
            continue;
        }

        let Ok(relative_path) = source_path.strip_prefix(root_dir) else {
            warnings.push(format!(
                "could not derive relative PowerShell path for {}",
                source_path.display()
            ));
            continue;
        };
        let archive_path = archive_root.join(relative_path);
        let live_path = join_live_path(live_root, relative_path);
        if is_reparse_or_symlink(&source_path) {
            push_skipped_file(
                source_path.as_path(),
                &live_path,
                &archive_path,
                profile_username,
                "reparse_or_symlink",
                skipped_files,
            );
            continue;
        }

        let metadata = match fs::metadata(&source_path) {
            Ok(metadata) => metadata,
            Err(error) => {
                warnings.push(format!("could not read metadata for {live_path}: {error}"));
                continue;
            }
        };
        let file_name = entry.file_name().to_string_lossy().to_string();
        if !is_allowed_recursive_extension(&file_name) {
            push_skipped_file(
                source_path.as_path(),
                &live_path,
                &archive_path,
                profile_username,
                "unsupported_extension",
                skipped_files,
            );
            continue;
        }
        if metadata.len() > MAX_RECURSIVE_FILE_SIZE_BYTES {
            push_skipped_file(
                source_path.as_path(),
                &live_path,
                &archive_path,
                profile_username,
                &format!("size_limit_exceeded:{}", MAX_RECURSIVE_FILE_SIZE_BYTES),
                skipped_files,
            );
            continue;
        }

        add_planned_file(
            &source_path,
            &live_path,
            &archive_path,
            profile_username,
            classify_recursive_file(directory_kind, &file_name),
            files,
            file_archive_paths,
            warnings,
        );
    }

    Ok(())
}

fn add_directory_record(
    source_path: &Path,
    live_path: &str,
    archive_path: &Path,
    profile_username: &str,
    directory_kind: PowerShellDirectoryKind,
    directory_records: &mut Vec<PowerShellActivityCollectedDirectory>,
    directory_archive_paths: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    let normalized_archive_path = normalize_archive_path_string(archive_path);
    if !directory_archive_paths.insert(normalized_archive_path.clone()) {
        return;
    }

    let metadata = match fs::metadata(source_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            warnings.push(format!(
                "could not read directory metadata for {}: {error}",
                source_path.display()
            ));
            return;
        }
    };

    let directory_name = source_path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| source_path.display().to_string());
    directory_records.push(PowerShellActivityCollectedDirectory {
        archive_path: normalized_archive_path,
        live_path: live_path.to_string(),
        vss_path: source_path.display().to_string(),
        profile_username: profile_username.to_string(),
        directory_kind,
        directory_name,
        created_utc: system_time_utc(metadata.created().ok()),
        modified_utc: system_time_utc(metadata.modified().ok()),
        accessed_utc: system_time_utc(metadata.accessed().ok()),
        source_file_attributes: source_file_attributes(&metadata),
        record_status: "recorded".to_string(),
    });
}

fn add_planned_file(
    source_path: &Path,
    live_path: &str,
    archive_path: &Path,
    profile_username: &str,
    artifact_kind: PowerShellArtifactKind,
    files: &mut Vec<PlannedPowerShellFile>,
    file_archive_paths: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    let normalized_archive_path = normalize_archive_path_string(archive_path);
    if !file_archive_paths.insert(normalized_archive_path) {
        return;
    }

    let file_name = match source_path.file_name() {
        Some(value) => value.to_string_lossy().to_string(),
        None => {
            warnings.push(format!(
                "PowerShell artifact had no final path component: {}",
                source_path.display()
            ));
            return;
        }
    };

    files.push(PlannedPowerShellFile {
        source_path: source_path.to_path_buf(),
        live_path: live_path.to_string(),
        archive_path: archive_path.to_path_buf(),
        profile_username: profile_username.to_string(),
        artifact_kind,
        file_name,
    });
}

fn push_skipped_file(
    source_path: &Path,
    live_path: &str,
    archive_path: &Path,
    profile_username: &str,
    reason: &str,
    skipped_files: &mut Vec<PowerShellActivitySkippedFile>,
) {
    let size = fs::metadata(source_path)
        .map(|metadata| metadata.len())
        .or_else(|_| fs::symlink_metadata(source_path).map(|metadata| metadata.len()))
        .unwrap_or(0);
    skipped_files.push(PowerShellActivitySkippedFile {
        profile_username: profile_username.to_string(),
        live_path: live_path.to_string(),
        vss_path: source_path.display().to_string(),
        archive_path: normalize_archive_path_string(archive_path),
        size,
        reason: reason.to_string(),
    });
}

fn classify_recursive_file(
    directory_kind: PowerShellDirectoryKind,
    file_name: &str,
) -> PowerShellArtifactKind {
    match directory_kind {
        PowerShellDirectoryKind::ModulesRoot => PowerShellArtifactKind::ModuleSupportFile,
        PowerShellDirectoryKind::TranscriptRoot => PowerShellArtifactKind::Transcript,
        PowerShellDirectoryKind::PowerShellDataRoot => {
            if file_name.eq_ignore_ascii_case("ConsoleHost_history.txt") {
                PowerShellArtifactKind::PsReadLineHistory
            } else {
                PowerShellArtifactKind::PowerShellDataFile
            }
        }
    }
}

fn matches_root_transcript_file(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower.starts_with("powershell_transcript") && lower.ends_with(".txt")
}

fn is_allowed_recursive_extension(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    ALLOWED_RECURSIVE_EXTENSIONS
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn powershell_activity_source_globs(volume: &str) -> Vec<String> {
    vec![
        format!(
            r"{volume}\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        ),
        format!(
            r"{volume}\Users\*\AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt"
        ),
        format!(r"{volume}\Users\*\Documents\WindowsPowerShell\*.ps1"),
        format!(r"{volume}\Users\*\Documents\PowerShell\*.ps1"),
        format!(r"{volume}\Users\*\Documents\PowerShell_transcript*.txt"),
        format!(r"{volume}\Users\*\Documents\WindowsPowerShell\Modules\**"),
        format!(r"{volume}\Users\*\Documents\PowerShell\Modules\**"),
        format!(r"{volume}\Users\*\Documents\WindowsPowerShell\Transcripts\**"),
        format!(r"{volume}\Users\*\Documents\PowerShell\Transcripts\**"),
        format!(r"{volume}\Users\*\AppData\Local\Microsoft\Windows\PowerShell\**"),
        format!(r"{volume}\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\**"),
        format!(r"{volume}\Users\*\AppData\Local\Microsoft\PowerShell\**"),
        format!(r"{volume}\Users\*\AppData\Roaming\Microsoft\PowerShell\**"),
    ]
}

fn materialize_output_path(output_root: &Path, stored_path: &str) -> PathBuf {
    let candidate = PathBuf::from(stored_path);
    if candidate.is_absolute() {
        candidate
    } else {
        output_root.join(stored_path.replace('/', "\\"))
    }
}

fn is_low_value_profile_name(profile_name: &str) -> bool {
    LOW_VALUE_PROFILE_NAMES.contains(&profile_name.trim().to_ascii_lowercase().as_str())
}

fn join_live_path(root: &str, relative_path: &Path) -> String {
    let relative = normalize_live_path_string(relative_path);
    if relative.is_empty() {
        root.to_string()
    } else {
        format!(r"{}\{}", root, relative)
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

fn copy_powershell_activity_file(
    planned_file: &PlannedPowerShellFile,
    destination_path: &Path,
) -> Result<PowerShellActivityCollectedFile> {
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "create PowerShell activity destination directory {}",
                parent.display()
            )
        })?;
    }

    let source_hash = sha256_file(&planned_file.source_path)
        .with_context(|| format!("hash source {}", planned_file.source_path.display()))?;
    fs::copy(&planned_file.source_path, destination_path).with_context(|| {
        format!(
            "copy PowerShell activity {} -> {}",
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
    Ok(PowerShellActivityCollectedFile {
        archive_path: normalize_archive_path_string(&planned_file.archive_path),
        live_path: planned_file.live_path.clone(),
        vss_path: planned_file.source_path.display().to_string(),
        profile_username: planned_file.profile_username.clone(),
        artifact_kind: planned_file.artifact_kind,
        file_name: planned_file.file_name.clone(),
        size: metadata.len(),
        created_utc: system_time_utc(metadata.created().ok()),
        modified_utc: system_time_utc(metadata.modified().ok()),
        accessed_utc: system_time_utc(metadata.accessed().ok()),
        source_file_attributes: source_file_attributes(&metadata),
        source_sha256: source_hash,
        sha256: destination_hash,
        copy_status: "success".to_string(),
    })
}

fn write_manifest(path: &Path, manifest: &PowerShellActivityCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create manifest directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(manifest)?;
    fs::write(path, bytes).with_context(|| format!("write manifest {}", path.display()))
}

fn write_collection_log(
    path: &Path,
    manifest: &PowerShellActivityCollectionManifest,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create collection log directory {}", parent.display()))?;
    }
    let file = File::create(path).with_context(|| format!("create log {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writeln!(
        writer,
        "powershell_activity collection volume={}",
        manifest.volume
    )?;
    writeln!(writer, "source_root={}", manifest.source_root)?;
    writeln!(
        writer,
        "max_file_size_bytes={}",
        manifest.max_file_size_bytes
    )?;
    writeln!(
        writer,
        "allowed_extensions={}",
        manifest.allowed_extensions.join(",")
    )?;
    writeln!(
        writer,
        "profiles_scanned={} profiles_skipped={} directories={} found={} copied={} skipped={} failed={}",
        manifest.total_profiles_scanned,
        manifest.total_profiles_skipped,
        manifest.total_directories_recorded,
        manifest.total_files_found,
        manifest.total_files_copied,
        manifest.total_files_skipped,
        manifest.total_files_failed
    )?;
    for directory in &manifest.directories {
        writeln!(
            writer,
            "directory {} modified={} user={}",
            directory.archive_path,
            directory.modified_utc.as_deref().unwrap_or("unknown"),
            directory.profile_username
        )?;
    }
    for entry in &manifest.files {
        writeln!(
            writer,
            "copied {} size={} sha256={} user={}",
            entry.archive_path, entry.size, entry.sha256, entry.profile_username
        )?;
    }
    for skipped in &manifest.skipped_files {
        writeln!(
            writer,
            "skipped {} size={} reason={} user={}",
            skipped.archive_path, skipped.size, skipped.reason, skipped.profile_username
        )?;
    }
    for failure in &manifest.failures {
        writeln!(
            writer,
            "failed {} operation={} error={} user={}",
            failure.archive_path, failure.operation, failure.error, failure.profile_username
        )?;
    }
    writer
        .flush()
        .context("flush PowerShell activity collection log")
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

#[cfg(target_os = "windows")]
fn source_file_attributes(metadata: &fs::Metadata) -> Option<u32> {
    Some(metadata.file_attributes())
}

#[cfg(not(target_os = "windows"))]
fn source_file_attributes(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

fn normalize_archive_path_string(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
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
fn relaunch_elevated(request: &PowerShellActivityCollectRequest) -> Result<()> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWDEFAULT;
    use windows::core::{PCWSTR, w};

    let current_exe = std::env::current_exe().context("resolve current executable path")?;
    let current_dir = std::env::current_dir().context("resolve current working directory")?;
    let mut parameters = vec![
        "collect-powershell-activity".to_string(),
        "--volume".to_string(),
        request.volume.clone(),
        "--out-dir".to_string(),
        request.out_dir.display().to_string(),
    ];
    if let Some(path) = request.manifest.as_ref() {
        parameters.push("--manifest".to_string());
        parameters.push(path.display().to_string());
    }
    if let Some(path) = request.collection_log.as_ref() {
        parameters.push("--collection-log".to_string());
        parameters.push(path.display().to_string());
    }
    if let Some(path) = request.diagnostic_log.as_ref() {
        parameters.push("--diagnostic-log".to_string());
        parameters.push(path.display().to_string());
    }

    let parameter_string = parameters
        .into_iter()
        .map(|value| quote_windows_argument(&value))
        .collect::<Vec<_>>()
        .join(" ");
    let exe_wide = encode_wide_os(current_exe.as_os_str());
    let dir_wide = encode_wide_os(current_dir.as_os_str());
    let parameters_wide = encode_wide(&parameter_string);

    let mut execute = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(exe_wide.as_ptr()),
        lpParameters: PCWSTR(parameters_wide.as_ptr()),
        lpDirectory: PCWSTR(dir_wide.as_ptr()),
        nShow: SW_SHOWDEFAULT.0,
        ..Default::default()
    };

    unsafe { ShellExecuteExW(&mut execute) }
        .context("launch elevated PowerShell activity collector")?;
    let process = execute.hProcess;
    if process.is_invalid() {
        bail!("UAC launch did not return a PowerShell activity process handle");
    }

    unsafe {
        WaitForSingleObject(process, INFINITE);
    }
    let mut exit_code = 0u32;
    unsafe {
        GetExitCodeProcess(process, &mut exit_code)
            .context("read elevated PowerShell activity exit code")?;
        let _ = CloseHandle(process);
    }
    if exit_code != 0 {
        bail!("elevated PowerShell activity collector exited with status {exit_code}");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn relaunch_elevated(_request: &PowerShellActivityCollectRequest) -> Result<()> {
    bail!("PowerShell activity elevation relaunch is only available on Windows")
}

#[cfg(target_os = "windows")]
fn encode_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn encode_wide_os(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn quote_windows_argument(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_string();
    }
    if !value.contains([' ', '\t', '"']) {
        return value.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for character in value.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    quoted.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                quoted.push(character);
            }
        }
    }
    if backslashes > 0 {
        quoted.push_str(&"\\".repeat(backslashes * 2));
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use anyhow::Result;
    use tempfile::tempdir;

    use super::{
        PowerShellArtifactKind, default_collection_log_path, default_manifest_path,
        plan_powershell_activity_files,
    };

    #[test]
    fn powershell_activity_default_paths_use_central_archive_root() -> Result<()> {
        let root = PathBuf::from(r"C:\temp\powershell-activity");

        assert_eq!(
            default_manifest_path(&root, "c:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_powershell_activity")
                .join("manifest.json")
        );
        assert_eq!(
            default_collection_log_path(&root, "c:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_powershell_activity")
                .join("collection.log")
        );
        Ok(())
    }

    #[test]
    fn powershell_activity_plan_collects_fixed_and_recursive_targets() -> Result<()> {
        let temp = tempdir()?;
        let source_root = temp.path().join("shadow");
        let alice_root = source_root.join("Users").join("alice");
        let history = alice_root
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("PowerShell")
            .join("PSReadLine");
        let profile_dir = alice_root.join("Documents").join("PowerShell");
        let module_dir = profile_dir.join("Modules").join("Tooling");
        let data_dir = alice_root
            .join("AppData")
            .join("Local")
            .join("Microsoft")
            .join("PowerShell");
        let public_history = source_root
            .join("Users")
            .join("Public")
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("PowerShell")
            .join("PSReadLine");

        fs::create_dir_all(&history)?;
        fs::create_dir_all(&module_dir)?;
        fs::create_dir_all(&data_dir)?;
        fs::create_dir_all(&public_history)?;
        fs::write(history.join("ConsoleHost_history.txt"), b"Get-ChildItem")?;
        fs::write(
            profile_dir.join("profile.ps1"),
            b"Set-StrictMode -Version Latest",
        )?;
        fs::write(
            alice_root
                .join("Documents")
                .join("PowerShell_transcript_20240512.txt"),
            b"transcript",
        )?;
        fs::write(module_dir.join("Tooling.psm1"), b"function Invoke-Thing {}")?;
        fs::write(data_dir.join("state.json"), br#"{"ok":true}"#)?;
        fs::write(data_dir.join("binary.dll"), b"dll")?;
        fs::write(
            module_dir.join("too-big.txt"),
            vec![b'a'; (20 * 1024 * 1024) + 1],
        )?;
        fs::write(
            public_history.join("ConsoleHost_history.txt"),
            b"skip public",
        )?;

        let plan = plan_powershell_activity_files("c:", &source_root)?;

        assert_eq!(plan.profiles_scanned, 2);
        assert_eq!(plan.profiles_skipped, 1);
        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Users")
                    .join("alice")
                    .join("AppData")
                    .join("Roaming")
                    .join("Microsoft")
                    .join("Windows")
                    .join("PowerShell")
                    .join("PSReadLine")
                    .join("ConsoleHost_history.txt")
                && matches!(
                    file.artifact_kind,
                    PowerShellArtifactKind::PsReadLineHistory
                )
        }));
        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Users")
                    .join("alice")
                    .join("Documents")
                    .join("PowerShell")
                    .join("profile.ps1")
                && matches!(file.artifact_kind, PowerShellArtifactKind::ProfileScript)
        }));
        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Users")
                    .join("alice")
                    .join("Documents")
                    .join("PowerShell_transcript_20240512.txt")
                && matches!(file.artifact_kind, PowerShellArtifactKind::Transcript)
        }));
        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Users")
                    .join("alice")
                    .join("Documents")
                    .join("PowerShell")
                    .join("Modules")
                    .join("Tooling")
                    .join("Tooling.psm1")
                && matches!(
                    file.artifact_kind,
                    PowerShellArtifactKind::ModuleSupportFile
                )
        }));
        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Users")
                    .join("alice")
                    .join("AppData")
                    .join("Local")
                    .join("Microsoft")
                    .join("PowerShell")
                    .join("state.json")
                && matches!(
                    file.artifact_kind,
                    PowerShellArtifactKind::PowerShellDataFile
                )
        }));
        assert!(
            plan.directory_records.iter().any(|record| {
                record.archive_path == "C/Users/alice/Documents/PowerShell/Modules"
            })
        );
        assert!(plan.skipped_files.iter().any(|record| {
            record.archive_path.ends_with("/binary.dll") && record.reason == "unsupported_extension"
        }));
        assert!(plan.skipped_files.iter().any(|record| {
            record.archive_path.ends_with("/too-big.txt")
                && record.reason.starts_with("size_limit_exceeded:")
        }));
        Ok(())
    }
}
