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

const MPLOGS_COLLECTION_SCHEMA: &str = "windows_mplogs_collection_v1";
const MPLOGS_COLLECTOR_NAME: &str = "windows_mplogs";
#[cfg(target_os = "windows")]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

#[derive(Debug, Clone, Args)]
pub struct MpLogsCollectCli {
    #[arg(long, help = "NTFS volume, for example C:")]
    pub volume: String,

    #[arg(
        long = "out-dir",
        help = "Output root directory for collected Microsoft Protection Logs artifacts"
    )]
    pub out_dir: PathBuf,

    #[arg(
        long,
        help = "Optional collection manifest path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_mplogs/manifest.json"
    )]
    pub manifest: Option<PathBuf>,

    #[arg(
        long = "collection-log",
        help = "Optional collection log path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_mplogs/collection.log"
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
pub struct MpLogsCollectRequest {
    pub volume: String,
    pub out_dir: PathBuf,
    pub manifest: Option<PathBuf>,
    pub collection_log: Option<PathBuf>,
    pub diagnostic_log: Option<PathBuf>,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct MpLogsCollectSummary {
    pub volume: String,
    pub output_root: PathBuf,
    pub manifest_path: PathBuf,
    pub collection_log_path: PathBuf,
    pub staged_paths: Vec<PathBuf>,
    pub file_records: Vec<MpLogsCollectedFile>,
    pub failures: Vec<MpLogsCollectionFailure>,
}

#[derive(Debug, Clone)]
pub struct MpLogsProgress {
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
pub enum MpLogsArtifactKind {
    SupportLog,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpLogsCollectedFile {
    pub archive_path: String,
    pub live_path: String,
    pub vss_path: String,
    pub artifact_kind: MpLogsArtifactKind,
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
pub struct MpLogsCollectionFailure {
    pub live_path: String,
    pub vss_path: String,
    pub archive_path: String,
    pub operation: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MpLogsCollectionManifest {
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
    total_files_found: usize,
    total_files_copied: usize,
    total_files_failed: usize,
    files: Vec<MpLogsCollectedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    failures: Vec<MpLogsCollectionFailure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct PlannedMpLogsFile {
    source_path: PathBuf,
    live_path: String,
    archive_path: PathBuf,
    artifact_kind: MpLogsArtifactKind,
    file_name: String,
}

struct MpLogsPlan {
    files: Vec<PlannedMpLogsFile>,
    warnings: Vec<String>,
}

pub fn run(args: &MpLogsCollectCli) -> Result<()> {
    let summary = collect(&MpLogsCollectRequest {
        volume: args.volume.clone(),
        out_dir: args.out_dir.clone(),
        manifest: args.manifest.clone(),
        collection_log: args.collection_log.clone(),
        diagnostic_log: args.diagnostic_log.clone(),
        elevate: args.elevate,
    })?;
    println!(
        "Collected {} Microsoft Protection Log files.",
        summary.file_records.len()
    );
    println!(
        "Failed {} Microsoft Protection Log files.",
        summary.failures.len()
    );
    println!("Manifest: {}", summary.manifest_path.display());
    println!("Collection log: {}", summary.collection_log_path.display());
    Ok(())
}

pub fn collect(request: &MpLogsCollectRequest) -> Result<MpLogsCollectSummary> {
    let mut reporter = |_| {};
    collect_with_progress(request, &mut reporter)
}

pub fn collect_with_progress(
    request: &MpLogsCollectRequest,
    reporter: &mut dyn FnMut(MpLogsProgress),
) -> Result<MpLogsCollectSummary> {
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
        reporter(MpLogsProgress {
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
        .with_context(|| format!("delete MPLogs shadow copy {}", shadow_copy.id));
    match (result, delete_result) {
        (Ok(summary), Ok(())) => {
            mark_shadow_deleted(&summary.manifest_path)?;
            Ok(summary)
        }
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(delete_error)) => Err(error.context(format!(
            "also failed to delete MPLogs shadow copy {}: {delete_error:#}",
            shadow_copy.id
        ))),
    }
}

pub fn collect_with_progress_using_shadow_copy(
    request: &MpLogsCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    reporter: &mut dyn FnMut(MpLogsProgress),
) -> Result<MpLogsCollectSummary> {
    validate_request(request)?;
    collect_from_shadow_copy(request, shadow_copy, true, reporter)
}

pub fn default_manifest_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_manifest_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_MPLOGS_COLLECTOR,
    )
}

pub fn default_collection_log_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_log_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_MPLOGS_COLLECTOR,
    )
}

pub fn default_diagnostic_log_path(_output_root: &Path) -> PathBuf {
    runtime_support::technical_log_path()
}

fn validate_request(request: &MpLogsCollectRequest) -> Result<()> {
    let _ = usn_journal::normalize_volume(&request.volume)?;
    if request.out_dir.as_os_str().is_empty() {
        bail!("--out-dir must not be empty");
    }
    Ok(())
}

fn collect_from_shadow_copy(
    request: &MpLogsCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    shared_shadow_copy: bool,
    reporter: &mut dyn FnMut(MpLogsProgress),
) -> Result<MpLogsCollectSummary> {
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
    reporter(MpLogsProgress {
        progress_value: 0.05,
        detail: format!("Enumerating Microsoft Protection Logs on {volume}."),
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

    let plan = plan_mplog_files(&volume, &source_root)?;
    warnings.extend(plan.warnings);
    let planned = plan.files;
    let total = planned.len();
    let mut staged_paths = Vec::new();
    let mut file_records = Vec::new();
    let mut failures = Vec::new();

    for (index, planned_file) in planned.into_iter().enumerate() {
        let archive_name = normalize_archive_path_string(&planned_file.archive_path);
        let destination_path = request.out_dir.join(&planned_file.archive_path);
        reporter(MpLogsProgress {
            progress_value: 0.08 + (0.82 * progress_fraction(index, total)),
            detail: format!("Copying {archive_name}"),
            progress_text: format!("{index} / {total} files"),
        });
        match copy_mplog_file(&planned_file, &destination_path) {
            Ok(record) => {
                staged_paths.push(destination_path);
                file_records.push(record);
            }
            Err(error) => failures.push(MpLogsCollectionFailure {
                live_path: planned_file.live_path,
                vss_path: planned_file.source_path.display().to_string(),
                archive_path: archive_name,
                operation: "copy_hash_verify".to_string(),
                error: error.to_string(),
            }),
        }
    }

    reporter(MpLogsProgress {
        progress_value: 0.94,
        detail: "Writing Microsoft Protection Logs manifest and collection log.".to_string(),
        progress_text: "Manifest".to_string(),
    });
    let end_time = Utc::now();
    let manifest = MpLogsCollectionManifest {
        metadata_schema: MPLOGS_COLLECTION_SCHEMA.to_string(),
        artifact_type: "windows_mplogs_collection".to_string(),
        artifact_name: "Windows Microsoft Protection Logs".to_string(),
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
            name: MPLOGS_COLLECTOR_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            language: "rust".to_string(),
        },
        transaction_safe: true,
        source_root: source_root.display().to_string(),
        source_globs: mplog_source_globs(&volume),
        privileges_enabled,
        shadow_copy: Some(ShadowCopyMetadata {
            created: !shared_shadow_copy,
            deleted: false,
            shared: shared_shadow_copy,
            id: shadow_copy.id.clone(),
            device_object: shadow_copy.device_object.clone(),
            context: shadow_copy.context.clone(),
        }),
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

    reporter(MpLogsProgress {
        progress_value: 1.0,
        detail: format!(
            "Copied {} of {} Microsoft Protection Log files from {volume}.",
            file_records.len(),
            total
        ),
        progress_text: format!("{} copied, {} failed", file_records.len(), failures.len()),
    });

    Ok(MpLogsCollectSummary {
        volume,
        output_root: request.out_dir.clone(),
        manifest_path,
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
    collection_log_path: &Path,
) -> Result<MpLogsCollectSummary> {
    let bytes = fs::read(manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let manifest: MpLogsCollectionManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode manifest {}", manifest_path.display()))?;
    let mut staged_paths = manifest
        .files
        .iter()
        .map(|record| output_root.join(record.archive_path.replace('/', "\\")))
        .collect::<Vec<_>>();
    staged_paths.push(manifest_path.to_path_buf());
    staged_paths.push(collection_log_path.to_path_buf());
    Ok(MpLogsCollectSummary {
        volume: volume.to_string(),
        output_root: output_root.to_path_buf(),
        manifest_path: manifest_path.to_path_buf(),
        collection_log_path: collection_log_path.to_path_buf(),
        staged_paths,
        file_records: manifest.files,
        failures: manifest.failures,
    })
}

fn plan_mplog_files(volume: &str, source_root: &Path) -> Result<MpLogsPlan> {
    let normalized_volume = usn_journal::normalize_volume(volume)?;
    let archive_root = volume_archive_root(&normalized_volume)?;
    let support_dir = source_root
        .join("ProgramData")
        .join("Microsoft")
        .join("Windows Defender")
        .join("Support");
    let live_root = format!(
        r"{}\ProgramData\Microsoft\Windows Defender\Support",
        normalized_volume
    );
    let archive_dir = archive_root
        .join("ProgramData")
        .join("Microsoft")
        .join("Windows Defender")
        .join("Support");

    let mut files = Vec::new();
    let mut warnings = Vec::new();
    let mut archive_paths = BTreeSet::new();

    if !support_dir.exists() {
        warnings.push(format!(
            "Microsoft Defender Support directory was not present in snapshot for {}",
            normalized_volume
        ));
        return Ok(MpLogsPlan { files, warnings });
    }
    if !support_dir.is_dir() {
        warnings.push(format!(
            "Microsoft Defender Support path was not a directory: {}",
            support_dir.display()
        ));
        return Ok(MpLogsPlan { files, warnings });
    }
    if is_reparse_or_symlink(&support_dir) {
        warnings.push(format!(
            "skipped reparse/symlink Microsoft Defender Support root: {}",
            support_dir.display()
        ));
        return Ok(MpLogsPlan { files, warnings });
    }

    let entries = match fs::read_dir(&support_dir) {
        Ok(entries) => entries,
        Err(error) => {
            warnings.push(format!(
                "could not enumerate {}: {error}",
                support_dir.display()
            ));
            return Ok(MpLogsPlan { files, warnings });
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(format!(
                    "could not read entry in {}: {error}",
                    support_dir.display()
                ));
                continue;
            }
        };
        let source_path = entry.path();
        if !source_path.is_file() {
            continue;
        }
        if is_reparse_or_symlink(&source_path) {
            warnings.push(format!(
                "skipped reparse/symlink MPLog file: {}",
                source_path.display()
            ));
            continue;
        }

        let file_name = entry.file_name().to_string_lossy().to_string();
        let lower_name = file_name.to_ascii_lowercase();
        if !lower_name.starts_with("mplog") || !lower_name.ends_with(".log") {
            continue;
        }

        let archive_path = archive_dir.join(&file_name);
        let normalized_archive_path = normalize_archive_path_string(&archive_path);
        if !archive_paths.insert(normalized_archive_path) {
            continue;
        }

        files.push(PlannedMpLogsFile {
            source_path,
            live_path: format!(r"{}\{}", live_root, file_name),
            archive_path,
            artifact_kind: MpLogsArtifactKind::SupportLog,
            file_name,
        });
    }

    if files.is_empty() {
        warnings.push(format!(
            "no MPLog*.log files were present in {}",
            support_dir.display()
        ));
    }

    files.sort_by_key(|file| file.archive_path.display().to_string().to_ascii_lowercase());

    Ok(MpLogsPlan { files, warnings })
}

fn mplog_source_globs(volume: &str) -> Vec<String> {
    vec![format!(
        r"{volume}\ProgramData\Microsoft\Windows Defender\Support\MPLog*.log"
    )]
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

fn copy_mplog_file(
    planned_file: &PlannedMpLogsFile,
    destination_path: &Path,
) -> Result<MpLogsCollectedFile> {
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create MPLogs destination directory {}", parent.display()))?;
    }

    let source_hash = sha256_file(&planned_file.source_path)
        .with_context(|| format!("hash source {}", planned_file.source_path.display()))?;
    fs::copy(&planned_file.source_path, destination_path).with_context(|| {
        format!(
            "copy MPLog {} -> {}",
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
    Ok(MpLogsCollectedFile {
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

fn write_manifest(path: &Path, manifest: &MpLogsCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create manifest directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(manifest)?;
    fs::write(path, bytes).with_context(|| format!("write manifest {}", path.display()))
}

fn write_collection_log(path: &Path, manifest: &MpLogsCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create collection log directory {}", parent.display()))?;
    }
    let file = File::create(path).with_context(|| format!("create log {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "mplogs collection volume={}", manifest.volume)?;
    writeln!(writer, "source_root={}", manifest.source_root)?;
    writeln!(writer, "source_globs={}", manifest.source_globs.join("; "))?;
    writeln!(
        writer,
        "found={} copied={} failed={}",
        manifest.total_files_found, manifest.total_files_copied, manifest.total_files_failed
    )?;
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
    writer.flush().context("flush MPLogs collection log")
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
fn relaunch_elevated(request: &MpLogsCollectRequest) -> Result<()> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWDEFAULT;
    use windows::core::{PCWSTR, w};

    let current_exe = std::env::current_exe().context("resolve current executable path")?;
    let current_dir = std::env::current_dir().context("resolve current working directory")?;
    let mut parameters = vec![
        "collect-mplogs".to_string(),
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

    unsafe { ShellExecuteExW(&mut execute) }.context("launch elevated MPLogs collector")?;
    let process = execute.hProcess;
    if process.is_invalid() {
        bail!("UAC launch did not return an MPLogs process handle");
    }

    unsafe {
        WaitForSingleObject(process, INFINITE);
    }
    let mut exit_code = 0u32;
    unsafe {
        GetExitCodeProcess(process, &mut exit_code).context("read elevated MPLogs exit code")?;
        let _ = CloseHandle(process);
    }
    if exit_code != 0 {
        bail!("elevated MPLogs collector exited with status {exit_code}");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn relaunch_elevated(_request: &MpLogsCollectRequest) -> Result<()> {
    bail!("MPLogs elevation relaunch is only available on Windows")
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
    if !value.contains([' ', '\t', '\"']) {
        return value.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for character in value.chars() {
        match character {
            '\\' => backslashes += 1,
            '\"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('\"');
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
    quoted.push('\"');
    quoted
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Result;
    use tempfile::tempdir;

    use super::{
        MpLogsArtifactKind, default_collection_log_path, default_manifest_path, plan_mplog_files,
    };

    #[test]
    fn mplogs_default_paths_use_central_archive_root() -> Result<()> {
        let root = PathBuf::from(r"C:\temp\mplogs");

        assert_eq!(
            default_manifest_path(&root, "c:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_mplogs")
                .join("manifest.json")
        );
        assert_eq!(
            default_collection_log_path(&root, "c:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_mplogs")
                .join("collection.log")
        );
        Ok(())
    }

    #[test]
    fn mplog_plan_collects_defender_support_logs_only() -> Result<()> {
        let temp = tempdir()?;
        let support = temp
            .path()
            .join("ProgramData")
            .join("Microsoft")
            .join("Windows Defender")
            .join("Support");
        std::fs::create_dir_all(&support)?;
        std::fs::write(support.join("MPLog-20260515-031210.log"), b"first")?;
        std::fs::write(support.join("mplog-current.log"), b"second")?;
        std::fs::write(support.join("MpCmdRun.log"), b"skip")?;
        std::fs::write(support.join("MPLog-20260515-031210.txt"), b"skip")?;
        std::fs::create_dir_all(support.join("nested"))?;
        std::fs::write(
            support.join("nested").join("MPLog-20260515-031211.log"),
            b"nested",
        )?;

        let plan = plan_mplog_files("c:", temp.path())?;

        assert_eq!(plan.files.len(), 2);
        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("ProgramData")
                    .join("Microsoft")
                    .join("Windows Defender")
                    .join("Support")
                    .join("MPLog-20260515-031210.log")
                && file.artifact_kind == MpLogsArtifactKind::SupportLog
        }));
        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("ProgramData")
                    .join("Microsoft")
                    .join("Windows Defender")
                    .join("Support")
                    .join("mplog-current.log")
                && file.artifact_kind == MpLogsArtifactKind::SupportLog
        }));
        assert!(
            plan.files
                .iter()
                .all(|file| !file.file_name.eq_ignore_ascii_case("MpCmdRun.log"))
        );
        Ok(())
    }
}
