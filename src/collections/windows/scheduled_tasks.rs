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

const SCHEDULED_TASKS_COLLECTION_SCHEMA: &str = "windows_scheduled_tasks_collection_v1";
const SCHEDULED_TASKS_COLLECTOR_NAME: &str = "windows_scheduled_tasks";
#[cfg(target_os = "windows")]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

#[derive(Debug, Clone, Args)]
pub struct ScheduledTasksCollectCli {
    #[arg(long, help = "NTFS volume, for example C:")]
    pub volume: String,

    #[arg(
        long = "out-dir",
        help = "Output root directory for collected scheduled task artifacts"
    )]
    pub out_dir: PathBuf,

    #[arg(
        long,
        help = "Optional collection manifest path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_scheduled_tasks/manifest.json"
    )]
    pub manifest: Option<PathBuf>,

    #[arg(
        long = "collection-log",
        help = "Optional collection log path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_scheduled_tasks/collection.log"
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
pub struct ScheduledTasksCollectRequest {
    pub volume: String,
    pub out_dir: PathBuf,
    pub manifest: Option<PathBuf>,
    pub collection_log: Option<PathBuf>,
    pub diagnostic_log: Option<PathBuf>,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct ScheduledTasksCollectSummary {
    pub volume: String,
    pub output_root: PathBuf,
    pub manifest_path: PathBuf,
    pub collection_log_path: PathBuf,
    pub staged_paths: Vec<PathBuf>,
    pub file_records: Vec<ScheduledTasksCollectedFile>,
    pub directory_records: Vec<ScheduledTasksCollectedDirectory>,
    pub failures: Vec<ScheduledTasksCollectionFailure>,
}

#[derive(Debug, Clone)]
pub struct ScheduledTasksProgress {
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
pub enum ScheduledTaskArtifactKind {
    LegacyJob,
    SchedulerLog,
    ModernDefinition,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledTaskDirectoryKind {
    LegacyTasksRoot,
    ModernTasksRoot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTasksCollectedFile {
    pub archive_path: String,
    pub live_path: String,
    pub vss_path: String,
    pub artifact_kind: ScheduledTaskArtifactKind,
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
pub struct ScheduledTasksCollectedDirectory {
    pub archive_path: String,
    pub live_path: String,
    pub vss_path: String,
    pub directory_kind: ScheduledTaskDirectoryKind,
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
pub struct ScheduledTasksCollectionFailure {
    pub live_path: String,
    pub vss_path: String,
    pub archive_path: String,
    pub operation: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScheduledTasksCollectionManifest {
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    privileges_enabled: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shadow_copy: Option<ShadowCopyMetadata>,
    total_sources_present: usize,
    total_directories_recorded: usize,
    total_files_found: usize,
    total_files_copied: usize,
    total_files_failed: usize,
    files: Vec<ScheduledTasksCollectedFile>,
    directories: Vec<ScheduledTasksCollectedDirectory>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    failures: Vec<ScheduledTasksCollectionFailure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct PlannedScheduledTaskFile {
    source_path: PathBuf,
    live_path: String,
    archive_path: PathBuf,
    artifact_kind: ScheduledTaskArtifactKind,
    file_name: String,
}

struct ScheduledTasksPlan {
    files: Vec<PlannedScheduledTaskFile>,
    directory_records: Vec<ScheduledTasksCollectedDirectory>,
    warnings: Vec<String>,
    sources_present: usize,
}

pub fn run(args: &ScheduledTasksCollectCli) -> Result<()> {
    let summary = collect(&ScheduledTasksCollectRequest {
        volume: args.volume.clone(),
        out_dir: args.out_dir.clone(),
        manifest: args.manifest.clone(),
        collection_log: args.collection_log.clone(),
        diagnostic_log: args.diagnostic_log.clone(),
        elevate: args.elevate,
    })?;
    println!(
        "Collected {} scheduled task files.",
        summary.file_records.len()
    );
    println!(
        "Recorded {} scheduled task directories.",
        summary.directory_records.len()
    );
    println!("Failed {} scheduled task files.", summary.failures.len());
    println!("Manifest: {}", summary.manifest_path.display());
    println!("Collection log: {}", summary.collection_log_path.display());
    Ok(())
}

pub fn collect(request: &ScheduledTasksCollectRequest) -> Result<ScheduledTasksCollectSummary> {
    let mut reporter = |_| {};
    collect_with_progress(request, &mut reporter)
}

pub fn collect_with_progress(
    request: &ScheduledTasksCollectRequest,
    reporter: &mut dyn FnMut(ScheduledTasksProgress),
) -> Result<ScheduledTasksCollectSummary> {
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
        reporter(ScheduledTasksProgress {
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
        .with_context(|| format!("delete scheduled tasks shadow copy {}", shadow_copy.id));
    match (result, delete_result) {
        (Ok(summary), Ok(())) => {
            mark_shadow_deleted(&summary.manifest_path)?;
            Ok(summary)
        }
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(delete_error)) => Err(error.context(format!(
            "also failed to delete scheduled tasks shadow copy {}: {delete_error:#}",
            shadow_copy.id
        ))),
    }
}

pub fn collect_with_progress_using_shadow_copy(
    request: &ScheduledTasksCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    reporter: &mut dyn FnMut(ScheduledTasksProgress),
) -> Result<ScheduledTasksCollectSummary> {
    validate_request(request)?;
    collect_from_shadow_copy(request, shadow_copy, true, reporter)
}

pub fn default_manifest_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_manifest_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_SCHEDULED_TASKS_COLLECTOR,
    )
}

pub fn default_collection_log_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_log_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_SCHEDULED_TASKS_COLLECTOR,
    )
}

pub fn default_diagnostic_log_path(_output_root: &Path) -> PathBuf {
    runtime_support::technical_log_path()
}

fn validate_request(request: &ScheduledTasksCollectRequest) -> Result<()> {
    let _ = usn_journal::normalize_volume(&request.volume)?;
    if request.out_dir.as_os_str().is_empty() {
        bail!("--out-dir must not be empty");
    }
    Ok(())
}

fn collect_from_shadow_copy(
    request: &ScheduledTasksCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    shared_shadow_copy: bool,
    reporter: &mut dyn FnMut(ScheduledTasksProgress),
) -> Result<ScheduledTasksCollectSummary> {
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
    reporter(ScheduledTasksProgress {
        progress_value: 0.05,
        detail: format!("Enumerating scheduled task artifacts on {volume}."),
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

    let planned = plan_scheduled_task_artifacts(&volume, &source_root)?;
    warnings.extend(planned.warnings);

    let total = planned.files.len();
    let directory_records = planned.directory_records;
    let mut staged_paths = Vec::new();
    let mut file_records = Vec::new();
    let mut failures = Vec::new();

    for (index, planned_file) in planned.files.into_iter().enumerate() {
        let archive_name = normalize_archive_path_string(&planned_file.archive_path);
        let destination_path = request.out_dir.join(&planned_file.archive_path);
        reporter(ScheduledTasksProgress {
            progress_value: 0.08 + (0.82 * progress_fraction(index, total)),
            detail: format!("Copying {archive_name}"),
            progress_text: format!("{index} / {total} files"),
        });
        match copy_scheduled_task_file(&planned_file, &destination_path) {
            Ok(record) => {
                staged_paths.push(destination_path);
                file_records.push(record);
            }
            Err(error) => failures.push(ScheduledTasksCollectionFailure {
                live_path: planned_file.live_path,
                vss_path: planned_file.source_path.display().to_string(),
                archive_path: archive_name,
                operation: "copy_hash_verify".to_string(),
                error: error.to_string(),
            }),
        }
    }

    reporter(ScheduledTasksProgress {
        progress_value: 0.94,
        detail: "Writing scheduled task manifest and collection log.".to_string(),
        progress_text: "Manifest".to_string(),
    });
    let end_time = Utc::now();
    let manifest = ScheduledTasksCollectionManifest {
        metadata_schema: SCHEDULED_TASKS_COLLECTION_SCHEMA.to_string(),
        artifact_type: "windows_scheduled_tasks_collection".to_string(),
        artifact_name: "Windows Scheduled Tasks".to_string(),
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
            name: SCHEDULED_TASKS_COLLECTOR_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            language: "rust".to_string(),
        },
        transaction_safe: true,
        source_root: source_root.display().to_string(),
        source_globs: scheduled_task_source_globs(&volume),
        privileges_enabled,
        shadow_copy: Some(ShadowCopyMetadata {
            created: !shared_shadow_copy,
            deleted: false,
            shared: shared_shadow_copy,
            id: shadow_copy.id.clone(),
            device_object: shadow_copy.device_object.clone(),
            context: shadow_copy.context.clone(),
        }),
        total_sources_present: planned.sources_present,
        total_directories_recorded: directory_records.len(),
        total_files_found: total,
        total_files_copied: file_records.len(),
        total_files_failed: failures.len(),
        files: file_records.clone(),
        directories: directory_records.clone(),
        failures: failures.clone(),
        warnings,
    };

    write_manifest(&manifest_path, &manifest)?;
    write_collection_log(&collection_log_path, &manifest)?;
    staged_paths.push(manifest_path.clone());
    staged_paths.push(collection_log_path.clone());

    reporter(ScheduledTasksProgress {
        progress_value: 1.0,
        detail: format!(
            "Copied {} of {} scheduled task files from {volume}.",
            file_records.len(),
            total
        ),
        progress_text: format!("{} copied, {} failed", file_records.len(), failures.len()),
    });

    Ok(ScheduledTasksCollectSummary {
        volume,
        output_root: request.out_dir.clone(),
        manifest_path,
        collection_log_path,
        staged_paths,
        file_records,
        directory_records,
        failures,
    })
}

fn load_existing_summary(
    volume: &str,
    output_root: &Path,
    manifest_path: &Path,
    collection_log_path: &Path,
) -> Result<ScheduledTasksCollectSummary> {
    let bytes = fs::read(manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let manifest: ScheduledTasksCollectionManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode manifest {}", manifest_path.display()))?;
    let mut staged_paths = manifest
        .files
        .iter()
        .map(|record| output_root.join(record.archive_path.replace('/', "\\")))
        .collect::<Vec<_>>();
    staged_paths.push(manifest_path.to_path_buf());
    staged_paths.push(collection_log_path.to_path_buf());
    Ok(ScheduledTasksCollectSummary {
        volume: volume.to_string(),
        output_root: output_root.to_path_buf(),
        manifest_path: manifest_path.to_path_buf(),
        collection_log_path: collection_log_path.to_path_buf(),
        staged_paths,
        file_records: manifest.files,
        directory_records: manifest.directories,
        failures: manifest.failures,
    })
}

fn plan_scheduled_task_artifacts(volume: &str, source_root: &Path) -> Result<ScheduledTasksPlan> {
    let normalized_volume = usn_journal::normalize_volume(volume)?;
    let archive_root = volume_archive_root(&normalized_volume)?;
    let mut files = Vec::new();
    let mut directory_records = Vec::new();
    let mut warnings = Vec::new();
    let mut file_archive_paths = BTreeSet::new();
    let mut directory_archive_paths = BTreeSet::new();
    let mut sources_present = 0usize;

    let legacy_tasks_dir = source_root.join("Windows").join("Tasks");
    if legacy_tasks_dir.exists() {
        if !legacy_tasks_dir.is_dir() {
            warnings.push(format!(
                "scheduled task legacy root was not a directory: {}",
                legacy_tasks_dir.display()
            ));
        } else if is_reparse_or_symlink(&legacy_tasks_dir) {
            warnings.push(format!(
                "skipped reparse/symlink scheduled task root: {}",
                legacy_tasks_dir.display()
            ));
        } else {
            sources_present += 1;
            collect_task_directory(
                &legacy_tasks_dir,
                &legacy_tasks_dir,
                &archive_root.join("Windows").join("Tasks"),
                &format!(r"{}\Windows\Tasks", normalized_volume),
                ScheduledTaskDirectoryKind::LegacyTasksRoot,
                &mut files,
                &mut directory_records,
                &mut file_archive_paths,
                &mut directory_archive_paths,
                &mut warnings,
            )?;
        }
    }

    let legacy_log = source_root.join("Windows").join("SchedLgU.txt");
    if legacy_log.exists() {
        if !legacy_log.is_file() {
            warnings.push(format!(
                "scheduled task legacy log was not a file: {}",
                legacy_log.display()
            ));
        } else if is_reparse_or_symlink(&legacy_log) {
            warnings.push(format!(
                "skipped reparse/symlink scheduled task log: {}",
                legacy_log.display()
            ));
        } else {
            sources_present += 1;
            add_planned_task_file(
                &legacy_log,
                &format!(r"{}\Windows\SchedLgU.txt", normalized_volume),
                &archive_root.join("Windows").join("SchedLgU.txt"),
                ScheduledTaskArtifactKind::SchedulerLog,
                &mut files,
                &mut file_archive_paths,
                &mut warnings,
            );
        }
    }

    let modern_tasks_dir = source_root.join("Windows").join("System32").join("Tasks");
    if modern_tasks_dir.exists() {
        if !modern_tasks_dir.is_dir() {
            warnings.push(format!(
                "scheduled task modern root was not a directory: {}",
                modern_tasks_dir.display()
            ));
        } else if is_reparse_or_symlink(&modern_tasks_dir) {
            warnings.push(format!(
                "skipped reparse/symlink scheduled task root: {}",
                modern_tasks_dir.display()
            ));
        } else {
            sources_present += 1;
            collect_task_directory(
                &modern_tasks_dir,
                &modern_tasks_dir,
                &archive_root.join("Windows").join("System32").join("Tasks"),
                &format!(r"{}\Windows\System32\Tasks", normalized_volume),
                ScheduledTaskDirectoryKind::ModernTasksRoot,
                &mut files,
                &mut directory_records,
                &mut file_archive_paths,
                &mut directory_archive_paths,
                &mut warnings,
            )?;
        }
    }

    if sources_present == 0 {
        warnings.push(format!(
            "no scheduled task roots were present in snapshot for {}",
            normalized_volume
        ));
    }

    files.sort_by_key(|file| file.archive_path.display().to_string().to_ascii_lowercase());
    directory_records.sort_by_key(|record| record.archive_path.to_ascii_lowercase());

    Ok(ScheduledTasksPlan {
        files,
        directory_records,
        warnings,
        sources_present,
    })
}

fn collect_task_directory(
    root_dir: &Path,
    current_dir: &Path,
    archive_root: &Path,
    live_root: &str,
    directory_kind: ScheduledTaskDirectoryKind,
    files: &mut Vec<PlannedScheduledTaskFile>,
    directory_records: &mut Vec<ScheduledTasksCollectedDirectory>,
    file_archive_paths: &mut BTreeSet<String>,
    directory_archive_paths: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
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
        directory_kind,
        directory_records,
        directory_archive_paths,
        warnings,
    );

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
                    "skipped reparse/symlink scheduled task directory: {}",
                    source_path.display()
                ));
                continue;
            }
            collect_task_directory(
                root_dir,
                &source_path,
                archive_root,
                live_root,
                directory_kind,
                files,
                directory_records,
                file_archive_paths,
                directory_archive_paths,
                warnings,
            )?;
            continue;
        }
        if !source_path.is_file() {
            continue;
        }
        if is_reparse_or_symlink(&source_path) {
            warnings.push(format!(
                "skipped reparse/symlink scheduled task file: {}",
                source_path.display()
            ));
            continue;
        }

        let Ok(relative_path) = source_path.strip_prefix(root_dir) else {
            warnings.push(format!(
                "could not derive relative scheduled task path for {}",
                source_path.display()
            ));
            continue;
        };
        let file_name = entry.file_name().to_string_lossy().to_string();
        add_planned_task_file(
            &source_path,
            &join_live_path(live_root, relative_path),
            &archive_root.join(relative_path),
            classify_task_file(directory_kind, &file_name),
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
    directory_kind: ScheduledTaskDirectoryKind,
    directory_records: &mut Vec<ScheduledTasksCollectedDirectory>,
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
    directory_records.push(ScheduledTasksCollectedDirectory {
        archive_path: normalized_archive_path,
        live_path: live_path.to_string(),
        vss_path: source_path.display().to_string(),
        directory_kind,
        directory_name,
        created_utc: system_time_utc(metadata.created().ok()),
        modified_utc: system_time_utc(metadata.modified().ok()),
        accessed_utc: system_time_utc(metadata.accessed().ok()),
        source_file_attributes: source_file_attributes(&metadata),
        record_status: "recorded".to_string(),
    });
}

fn add_planned_task_file(
    source_path: &Path,
    live_path: &str,
    archive_path: &Path,
    artifact_kind: ScheduledTaskArtifactKind,
    files: &mut Vec<PlannedScheduledTaskFile>,
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
                "scheduled task file had no final path component: {}",
                source_path.display()
            ));
            return;
        }
    };

    files.push(PlannedScheduledTaskFile {
        source_path: source_path.to_path_buf(),
        live_path: live_path.to_string(),
        archive_path: archive_path.to_path_buf(),
        artifact_kind,
        file_name,
    });
}

fn classify_task_file(
    directory_kind: ScheduledTaskDirectoryKind,
    file_name: &str,
) -> ScheduledTaskArtifactKind {
    match directory_kind {
        ScheduledTaskDirectoryKind::LegacyTasksRoot => {
            if file_name.eq_ignore_ascii_case("SchedLgU.txt") {
                ScheduledTaskArtifactKind::SchedulerLog
            } else if file_name.to_ascii_lowercase().ends_with(".job") {
                ScheduledTaskArtifactKind::LegacyJob
            } else {
                ScheduledTaskArtifactKind::Other
            }
        }
        ScheduledTaskDirectoryKind::ModernTasksRoot => ScheduledTaskArtifactKind::ModernDefinition,
    }
}

fn scheduled_task_source_globs(volume: &str) -> Vec<String> {
    vec![
        format!(r"{volume}\Windows\Tasks\**"),
        format!(r"{volume}\Windows\SchedLgU.txt"),
        format!(r"{volume}\Windows\System32\Tasks\**"),
    ]
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

fn copy_scheduled_task_file(
    planned_file: &PlannedScheduledTaskFile,
    destination_path: &Path,
) -> Result<ScheduledTasksCollectedFile> {
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "create scheduled task destination directory {}",
                parent.display()
            )
        })?;
    }

    let source_hash = sha256_file(&planned_file.source_path)
        .with_context(|| format!("hash source {}", planned_file.source_path.display()))?;
    fs::copy(&planned_file.source_path, destination_path).with_context(|| {
        format!(
            "copy scheduled task {} -> {}",
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
    Ok(ScheduledTasksCollectedFile {
        archive_path: normalize_archive_path_string(&planned_file.archive_path),
        live_path: planned_file.live_path.clone(),
        vss_path: planned_file.source_path.display().to_string(),
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

fn write_manifest(path: &Path, manifest: &ScheduledTasksCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create manifest directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(manifest)?;
    fs::write(path, bytes).with_context(|| format!("write manifest {}", path.display()))
}

fn write_collection_log(path: &Path, manifest: &ScheduledTasksCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create collection log directory {}", parent.display()))?;
    }
    let file = File::create(path).with_context(|| format!("create log {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writeln!(
        writer,
        "scheduled_tasks collection volume={}",
        manifest.volume
    )?;
    writeln!(writer, "source_root={}", manifest.source_root)?;
    writeln!(
        writer,
        "sources_present={} directories={} found={} copied={} failed={}",
        manifest.total_sources_present,
        manifest.total_directories_recorded,
        manifest.total_files_found,
        manifest.total_files_copied,
        manifest.total_files_failed
    )?;
    for directory in &manifest.directories {
        writeln!(
            writer,
            "directory {} modified={}",
            directory.archive_path,
            directory.modified_utc.as_deref().unwrap_or("unknown")
        )?;
    }
    for entry in &manifest.files {
        writeln!(
            writer,
            "copied {} size={} sha256={}",
            entry.archive_path, entry.size, entry.sha256
        )?;
    }
    for failure in &manifest.failures {
        writeln!(
            writer,
            "failed {} operation={} error={}",
            failure.archive_path, failure.operation, failure.error
        )?;
    }
    writer
        .flush()
        .context("flush scheduled tasks collection log")
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
fn relaunch_elevated(request: &ScheduledTasksCollectRequest) -> Result<()> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWDEFAULT;
    use windows::core::{PCWSTR, w};

    let current_exe = std::env::current_exe().context("resolve current executable path")?;
    let current_dir = std::env::current_dir().context("resolve current working directory")?;
    let mut parameters = vec![
        "collect-scheduled-tasks".to_string(),
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
        .context("launch elevated scheduled tasks collector")?;
    let process = execute.hProcess;
    if process.is_invalid() {
        bail!("UAC launch did not return a scheduled tasks process handle");
    }

    unsafe {
        WaitForSingleObject(process, INFINITE);
    }
    let mut exit_code = 0u32;
    unsafe {
        GetExitCodeProcess(process, &mut exit_code)
            .context("read elevated scheduled tasks exit code")?;
        let _ = CloseHandle(process);
    }
    if exit_code != 0 {
        bail!("elevated scheduled tasks collector exited with status {exit_code}");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn relaunch_elevated(_request: &ScheduledTasksCollectRequest) -> Result<()> {
    bail!("scheduled tasks elevation relaunch is only available on Windows")
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
    use std::path::PathBuf;

    use anyhow::Result;
    use tempfile::tempdir;

    use super::{
        ScheduledTaskArtifactKind, default_collection_log_path, default_manifest_path,
        plan_scheduled_task_artifacts,
    };

    #[test]
    fn scheduled_tasks_default_paths_use_central_archive_root() -> Result<()> {
        let root = PathBuf::from(r"C:\temp\scheduled-tasks");

        assert_eq!(
            default_manifest_path(&root, "c:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_scheduled_tasks")
                .join("manifest.json")
        );
        assert_eq!(
            default_collection_log_path(&root, "c:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_scheduled_tasks")
                .join("collection.log")
        );
        Ok(())
    }

    #[test]
    fn scheduled_tasks_plan_collects_legacy_and_modern_roots() -> Result<()> {
        let temp = tempdir()?;
        let windows = temp.path().join("Windows");
        let legacy = windows.join("Tasks");
        let modern = windows.join("System32").join("Tasks").join("Microsoft");
        std::fs::create_dir_all(&legacy)?;
        std::fs::create_dir_all(&modern)?;
        std::fs::write(legacy.join("Backup.job"), b"legacy")?;
        std::fs::write(legacy.join("SchedLgU.txt"), b"legacy log")?;
        std::fs::write(windows.join("SchedLgU.txt"), b"legacy root log")?;
        std::fs::write(modern.join("NightlyTask"), b"<Task />")?;

        let plan = plan_scheduled_task_artifacts("c:", temp.path())?;

        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Windows")
                    .join("Tasks")
                    .join("Backup.job")
                && matches!(file.artifact_kind, ScheduledTaskArtifactKind::LegacyJob)
        }));
        assert!(plan.files.iter().any(|file| {
            file.archive_path == PathBuf::from("C").join("Windows").join("SchedLgU.txt")
                && matches!(file.artifact_kind, ScheduledTaskArtifactKind::SchedulerLog)
        }));
        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Windows")
                    .join("System32")
                    .join("Tasks")
                    .join("Microsoft")
                    .join("NightlyTask")
                && matches!(
                    file.artifact_kind,
                    ScheduledTaskArtifactKind::ModernDefinition
                )
        }));
        assert!(
            plan.directory_records
                .iter()
                .any(|record| record.archive_path == "C/Windows/Tasks")
        );
        assert!(
            plan.directory_records
                .iter()
                .any(|record| record.archive_path == "C/Windows/System32/Tasks/Microsoft")
        );
        assert_eq!(plan.sources_present, 3);
        Ok(())
    }
}
