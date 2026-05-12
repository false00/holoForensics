#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
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

const PREFETCH_COLLECTION_SCHEMA: &str = "windows_prefetch_collection_v1";
const PREFETCH_COLLECTOR_NAME: &str = "windows_prefetch";

#[derive(Debug, Clone, Args)]
pub struct PrefetchCollectCli {
    #[arg(long, help = "NTFS volume, for example C:")]
    pub volume: String,

    #[arg(
        long = "out-dir",
        help = "Output root directory for collected Prefetch artifacts"
    )]
    pub out_dir: PathBuf,

    #[arg(
        long,
        help = "Optional collection manifest path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_prefetch/manifest.json"
    )]
    pub manifest: Option<PathBuf>,

    #[arg(
        long = "collection-log",
        help = "Optional collection log path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_prefetch/collection.log"
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
pub struct PrefetchCollectRequest {
    pub volume: String,
    pub out_dir: PathBuf,
    pub manifest: Option<PathBuf>,
    pub collection_log: Option<PathBuf>,
    pub diagnostic_log: Option<PathBuf>,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct PrefetchCollectSummary {
    pub volume: String,
    pub output_root: PathBuf,
    pub manifest_path: PathBuf,
    pub collection_log_path: PathBuf,
    pub staged_paths: Vec<PathBuf>,
    pub file_records: Vec<PrefetchCollectedFile>,
    pub failures: Vec<PrefetchCollectionFailure>,
}

#[derive(Debug, Clone)]
pub struct PrefetchProgress {
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
pub enum PrefetchArtifactKind {
    ApplicationPrefetch,
    BootPrefetch,
    LayoutIni,
    SuperfetchDatabase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchCollectedFile {
    pub archive_path: String,
    pub live_path: String,
    pub vss_path: String,
    pub artifact_kind: PrefetchArtifactKind,
    pub file_name: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessed_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_attributes: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_attribute_flags: Vec<String>,
    pub source_sha256: String,
    pub sha256: String,
    pub copy_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchCollectionFailure {
    pub live_path: String,
    pub vss_path: String,
    pub archive_path: String,
    pub operation: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrefetchCollectionManifest {
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
    files: Vec<PrefetchCollectedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    failures: Vec<PrefetchCollectionFailure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct PlannedPrefetchFile {
    source_path: PathBuf,
    live_path: String,
    archive_path: PathBuf,
    artifact_kind: PrefetchArtifactKind,
    file_name: String,
}

struct PrefetchPlan {
    files: Vec<PlannedPrefetchFile>,
    warnings: Vec<String>,
}

pub fn run(args: &PrefetchCollectCli) -> Result<()> {
    let summary = collect(&PrefetchCollectRequest {
        volume: args.volume.clone(),
        out_dir: args.out_dir.clone(),
        manifest: args.manifest.clone(),
        collection_log: args.collection_log.clone(),
        diagnostic_log: args.diagnostic_log.clone(),
        elevate: args.elevate,
    })?;
    println!("Collected {} Prefetch files.", summary.file_records.len());
    println!("Failed {} Prefetch files.", summary.failures.len());
    println!("Manifest: {}", summary.manifest_path.display());
    println!("Collection log: {}", summary.collection_log_path.display());
    Ok(())
}

pub fn collect(request: &PrefetchCollectRequest) -> Result<PrefetchCollectSummary> {
    let mut reporter = |_| {};
    collect_with_progress(request, &mut reporter)
}

pub fn collect_with_progress(
    request: &PrefetchCollectRequest,
    reporter: &mut dyn FnMut(PrefetchProgress),
) -> Result<PrefetchCollectSummary> {
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
        reporter(PrefetchProgress {
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
        .with_context(|| format!("delete Prefetch shadow copy {}", shadow_copy.id));
    match (result, delete_result) {
        (Ok(summary), Ok(())) => {
            mark_shadow_deleted(&summary.manifest_path)?;
            Ok(summary)
        }
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(delete_error)) => Err(error.context(format!(
            "also failed to delete Prefetch shadow copy {}: {delete_error:#}",
            shadow_copy.id
        ))),
    }
}

pub fn collect_with_progress_using_shadow_copy(
    request: &PrefetchCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    reporter: &mut dyn FnMut(PrefetchProgress),
) -> Result<PrefetchCollectSummary> {
    validate_request(request)?;
    collect_from_shadow_copy(request, shadow_copy, true, reporter)
}

pub fn default_manifest_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_manifest_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_PREFETCH_COLLECTOR,
    )
}

pub fn default_collection_log_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_log_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_PREFETCH_COLLECTOR,
    )
}

pub fn default_diagnostic_log_path(_output_root: &Path) -> PathBuf {
    runtime_support::technical_log_path()
}

fn validate_request(request: &PrefetchCollectRequest) -> Result<()> {
    let _ = usn_journal::normalize_volume(&request.volume)?;
    if request.out_dir.as_os_str().is_empty() {
        bail!("--out-dir must not be empty");
    }
    Ok(())
}

fn collect_from_shadow_copy(
    request: &PrefetchCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    shared_shadow_copy: bool,
    reporter: &mut dyn FnMut(PrefetchProgress),
) -> Result<PrefetchCollectSummary> {
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
    reporter(PrefetchProgress {
        progress_value: 0.05,
        detail: format!("Enumerating Prefetch files on {volume}."),
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

    let plan = plan_prefetch_files(&volume, &source_root)?;
    warnings.extend(plan.warnings);
    let planned = plan.files;
    let total = planned.len();
    let mut staged_paths = Vec::new();
    let mut file_records = Vec::new();
    let mut failures = Vec::new();

    for (index, planned_file) in planned.into_iter().enumerate() {
        let archive_name = normalize_archive_path_string(&planned_file.archive_path);
        let destination_path = request.out_dir.join(&planned_file.archive_path);
        reporter(PrefetchProgress {
            progress_value: 0.08 + (0.82 * progress_fraction(index, total)),
            detail: format!("Copying {archive_name}"),
            progress_text: format!("{index} / {total} Prefetch"),
        });
        match copy_prefetch_file(&planned_file, &destination_path) {
            Ok(record) => {
                staged_paths.push(destination_path);
                file_records.push(record);
            }
            Err(error) => failures.push(PrefetchCollectionFailure {
                live_path: planned_file.live_path,
                vss_path: planned_file.source_path.display().to_string(),
                archive_path: archive_name,
                operation: "copy_hash_verify".to_string(),
                error: error.to_string(),
            }),
        }
    }

    reporter(PrefetchProgress {
        progress_value: 0.94,
        detail: "Writing Prefetch manifest and collection log.".to_string(),
        progress_text: "Manifest".to_string(),
    });
    let end_time = Utc::now();
    let manifest = PrefetchCollectionManifest {
        metadata_schema: PREFETCH_COLLECTION_SCHEMA.to_string(),
        artifact_type: "windows_prefetch_collection".to_string(),
        artifact_name: "Windows Prefetch".to_string(),
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
            name: PREFETCH_COLLECTOR_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            language: "rust".to_string(),
        },
        transaction_safe: true,
        source_root: source_root.display().to_string(),
        source_globs: prefetch_source_globs(&volume),
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

    reporter(PrefetchProgress {
        progress_value: 1.0,
        detail: format!(
            "Copied {} of {} Prefetch files from {volume}.",
            file_records.len(),
            total
        ),
        progress_text: format!("{} copied, {} failed", file_records.len(), failures.len()),
    });

    Ok(PrefetchCollectSummary {
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
) -> Result<PrefetchCollectSummary> {
    let bytes = fs::read(manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let manifest: PrefetchCollectionManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode manifest {}", manifest_path.display()))?;
    let mut staged_paths = manifest
        .files
        .iter()
        .map(|record| output_root.join(record.archive_path.replace('/', "\\")))
        .collect::<Vec<_>>();
    staged_paths.push(manifest_path.to_path_buf());
    staged_paths.push(collection_log_path.to_path_buf());
    Ok(PrefetchCollectSummary {
        volume: volume.to_string(),
        output_root: output_root.to_path_buf(),
        manifest_path: manifest_path.to_path_buf(),
        collection_log_path: collection_log_path.to_path_buf(),
        staged_paths,
        file_records: manifest.files,
        failures: manifest.failures,
    })
}

fn plan_prefetch_files(volume: &str, source_root: &Path) -> Result<PrefetchPlan> {
    let normalized_volume = usn_journal::normalize_volume(volume)?;
    let prefetch_dir = source_root.join("Windows").join("Prefetch");
    let archive_root = volume_archive_root(&normalized_volume)?;
    let live_prefetch_root = format!(r"{normalized_volume}\Windows\Prefetch");
    let mut planned = Vec::new();
    let mut warnings = Vec::new();
    let mut archive_paths = BTreeSet::new();

    if !prefetch_dir.exists() {
        warnings.push(format!(
            "prefetch directory was not present in snapshot: {}",
            prefetch_dir.display()
        ));
        return Ok(PrefetchPlan {
            files: planned,
            warnings,
        });
    }
    if !prefetch_dir.is_dir() {
        warnings.push(format!(
            "prefetch path was not a directory in snapshot: {}",
            prefetch_dir.display()
        ));
        return Ok(PrefetchPlan {
            files: planned,
            warnings,
        });
    }

    for entry in fs::read_dir(&prefetch_dir)
        .with_context(|| format!("read Prefetch directory {}", prefetch_dir.display()))?
    {
        let entry = entry.with_context(|| format!("read entry in {}", prefetch_dir.display()))?;
        let source_path = entry.path();
        if !source_path.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let file_name_text = file_name.to_string_lossy().to_string();
        let Some(artifact_kind) = prefetch_artifact_kind(&file_name_text) else {
            continue;
        };
        let archive_path = archive_root
            .join("Windows")
            .join("Prefetch")
            .join(&file_name);
        if !archive_paths.insert(normalize_archive_path_string(&archive_path)) {
            continue;
        }
        planned.push(PlannedPrefetchFile {
            source_path,
            live_path: format!(r"{live_prefetch_root}\{file_name_text}"),
            archive_path,
            artifact_kind,
            file_name: file_name_text,
        });
    }

    planned.sort_by_key(|file| file.archive_path.display().to_string().to_ascii_lowercase());
    Ok(PrefetchPlan {
        files: planned,
        warnings,
    })
}

fn prefetch_artifact_kind(file_name: &str) -> Option<PrefetchArtifactKind> {
    let lower = file_name.to_ascii_lowercase();
    if lower == "layout.ini" {
        Some(PrefetchArtifactKind::LayoutIni)
    } else if lower.starts_with("ag") && lower.ends_with(".db") {
        Some(PrefetchArtifactKind::SuperfetchDatabase)
    } else if lower == "ntosboot-b00dfaad.pf" {
        Some(PrefetchArtifactKind::BootPrefetch)
    } else if lower.ends_with(".pf") {
        Some(PrefetchArtifactKind::ApplicationPrefetch)
    } else {
        None
    }
}

fn copy_prefetch_file(
    planned_file: &PlannedPrefetchFile,
    destination_path: &Path,
) -> Result<PrefetchCollectedFile> {
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("create Prefetch destination directory {}", parent.display())
        })?;
    }
    let source_hash = stream_copy_with_hash(&planned_file.source_path, destination_path)
        .with_context(|| {
            format!(
                "copy Prefetch {} -> {}",
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
    Ok(PrefetchCollectedFile {
        archive_path: normalize_archive_path_string(&planned_file.archive_path),
        live_path: planned_file.live_path.clone(),
        vss_path: planned_file.source_path.display().to_string(),
        artifact_kind: planned_file.artifact_kind,
        file_name: planned_file.file_name.clone(),
        size: metadata.len(),
        created_utc: system_time_utc(metadata.created().ok()),
        modified_utc: system_time_utc(metadata.modified().ok()),
        accessed_utc: system_time_utc(metadata.accessed().ok()),
        file_attributes: source_file_attributes(&metadata),
        file_attribute_flags: source_file_attribute_flags(&metadata),
        source_sha256: source_hash.clone(),
        sha256: destination_hash,
        copy_status: "success".to_string(),
    })
}

fn stream_copy_with_hash(source_path: &Path, destination_path: &Path) -> Result<String> {
    let mut source = File::open(source_path)
        .with_context(|| format!("open source {}", source_path.display()))?;
    let destination = File::create(destination_path)
        .with_context(|| format!("create destination {}", destination_path.display()))?;
    let mut writer = BufWriter::new(destination);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];

    loop {
        let bytes_read = source
            .read(&mut buffer)
            .with_context(|| format!("read {}", source_path.display()))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
        writer
            .write_all(&buffer[..bytes_read])
            .with_context(|| format!("write {}", destination_path.display()))?;
    }
    writer
        .flush()
        .with_context(|| format!("flush {}", destination_path.display()))?;

    Ok(format!("{:x}", hasher.finalize()))
}

fn prefetch_source_globs(volume: &str) -> Vec<String> {
    vec![
        format!(r"{volume}\Windows\Prefetch\*.pf"),
        format!(r"{volume}\Windows\Prefetch\Layout.ini"),
        format!(r"{volume}\Windows\Prefetch\Ag*.db"),
    ]
}

fn write_manifest(path: &Path, manifest: &PrefetchCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create manifest directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(manifest)?;
    fs::write(path, bytes).with_context(|| format!("write manifest {}", path.display()))
}

fn write_collection_log(path: &Path, manifest: &PrefetchCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create collection log directory {}", parent.display()))?;
    }
    let file = File::create(path).with_context(|| format!("create log {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "prefetch collection volume={}", manifest.volume)?;
    writeln!(writer, "source_root={}", manifest.source_root)?;
    writeln!(writer, "source_globs={}", manifest.source_globs.join("; "))?;
    if let Some(shadow_copy) = manifest.shadow_copy.as_ref() {
        writeln!(
            writer,
            "shadow_copy id={} device_object={} context={} created={} shared={} deleted={}",
            shadow_copy.id,
            shadow_copy.device_object,
            shadow_copy.context,
            shadow_copy.created,
            shadow_copy.shared,
            shadow_copy.deleted
        )?;
    }
    writeln!(
        writer,
        "found={} copied={} failed={}",
        manifest.total_files_found, manifest.total_files_copied, manifest.total_files_failed
    )?;
    for entry in &manifest.files {
        writeln!(
            writer,
            "copied {} kind={} size={} sha256={} attributes={:?} flags={}",
            entry.archive_path,
            prefetch_kind_name(entry.artifact_kind),
            entry.size,
            entry.sha256,
            entry.file_attributes,
            entry.file_attribute_flags.join("|")
        )?;
    }
    for failure in &manifest.failures {
        writeln!(
            writer,
            "failed {} operation={} error={}",
            failure.archive_path, failure.operation, failure.error
        )?;
    }
    writer.flush().context("flush Prefetch collection log")
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

fn prefetch_kind_name(kind: PrefetchArtifactKind) -> &'static str {
    match kind {
        PrefetchArtifactKind::ApplicationPrefetch => "application_prefetch",
        PrefetchArtifactKind::BootPrefetch => "boot_prefetch",
        PrefetchArtifactKind::LayoutIni => "layout_ini",
        PrefetchArtifactKind::SuperfetchDatabase => "superfetch_database",
    }
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

#[cfg(target_os = "windows")]
fn source_file_attribute_flags(metadata: &fs::Metadata) -> Vec<String> {
    file_attribute_flags(metadata.file_attributes())
}

#[cfg(not(target_os = "windows"))]
fn source_file_attribute_flags(_metadata: &fs::Metadata) -> Vec<String> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn file_attribute_flags(file_attributes: u32) -> Vec<String> {
    [
        (0x0000_0001, "readonly"),
        (0x0000_0002, "hidden"),
        (0x0000_0004, "system"),
        (0x0000_0010, "directory"),
        (0x0000_0020, "archive"),
        (0x0000_0080, "normal"),
        (0x0000_0100, "temporary"),
        (0x0000_0200, "sparse_file"),
        (0x0000_0400, "reparse_point"),
        (0x0000_0800, "compressed"),
        (0x0000_1000, "offline"),
        (0x0000_2000, "not_content_indexed"),
        (0x0000_4000, "encrypted"),
        (0x0000_8000, "integrity_stream"),
        (0x0002_0000, "no_scrub_data"),
        (0x0008_0000, "pinned"),
        (0x0010_0000, "unpinned"),
        (0x0040_0000, "recall_on_data_access"),
    ]
    .into_iter()
    .filter_map(|(flag, name)| {
        if file_attributes & flag != 0 {
            Some(name.to_string())
        } else {
            None
        }
    })
    .collect()
}

#[cfg(not(target_os = "windows"))]
fn file_attribute_flags(_file_attributes: u32) -> Vec<String> {
    Vec::new()
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
fn relaunch_elevated(request: &PrefetchCollectRequest) -> Result<()> {
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
        .context("launch elevated Prefetch collector via UAC")?;
    if execute.hProcess.is_invalid() {
        bail!("UAC launch did not return a process handle to wait on");
    }

    unsafe {
        WaitForSingleObject(execute.hProcess, INFINITE);
    }
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(execute.hProcess, &mut exit_code) }
        .context("read elevated Prefetch collector exit code")?;
    let _ = unsafe { CloseHandle(execute.hProcess) };
    if exit_code != 0 {
        bail!("elevated Prefetch collector exited with status {exit_code}");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn relaunch_elevated(_request: &PrefetchCollectRequest) -> Result<()> {
    bail!("Prefetch elevation relaunch is only available on Windows")
}

fn build_relaunch_parameters(request: &PrefetchCollectRequest) -> String {
    let mut values = vec![
        "collect-prefetch".to_string(),
        "--volume".to_string(),
        request.volume.clone(),
        "--out-dir".to_string(),
        request.out_dir.display().to_string(),
    ];

    if let Some(manifest) = request.manifest.as_ref() {
        values.push("--manifest".to_string());
        values.push(manifest.display().to_string());
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
    use std::path::PathBuf;

    use anyhow::Result;
    use tempfile::tempdir;

    use super::{
        PrefetchArtifactKind, default_collection_log_path, default_manifest_path,
        plan_prefetch_files,
    };

    #[test]
    fn default_prefetch_metadata_paths_live_under_central_collector_root() -> Result<()> {
        let root = PathBuf::from(r"C:\evidence");
        assert_eq!(
            default_manifest_path(&root, "c:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_prefetch")
                .join("manifest.json")
        );
        assert_eq!(
            default_collection_log_path(&root, r"\\?\C:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_prefetch")
                .join("collection.log")
        );
        Ok(())
    }

    #[test]
    fn plan_prefetch_files_collects_targeted_prefetch_artifacts() -> Result<()> {
        let temp = tempdir()?;
        let source_root = temp.path().join("shadow");
        let prefetch = source_root.join("Windows").join("Prefetch");
        fs::create_dir_all(&prefetch)?;
        fs::write(prefetch.join("APP-12345678.pf"), b"app")?;
        fs::write(prefetch.join("NTOSBOOT-B00DFAAD.pf"), b"boot")?;
        fs::write(prefetch.join("Layout.ini"), b"layout")?;
        fs::write(prefetch.join("AgGlGlobalHistory.db"), b"ag")?;
        fs::write(prefetch.join("ignored.txt"), b"ignore")?;

        let plan = plan_prefetch_files("c:", &source_root)?;

        assert_eq!(plan.files.len(), 4);
        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Windows")
                    .join("Prefetch")
                    .join("APP-12345678.pf")
                && file.artifact_kind == PrefetchArtifactKind::ApplicationPrefetch
        }));
        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Windows")
                    .join("Prefetch")
                    .join("NTOSBOOT-B00DFAAD.pf")
                && file.artifact_kind == PrefetchArtifactKind::BootPrefetch
        }));
        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Windows")
                    .join("Prefetch")
                    .join("Layout.ini")
                && file.artifact_kind == PrefetchArtifactKind::LayoutIni
        }));
        assert!(plan.files.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Windows")
                    .join("Prefetch")
                    .join("AgGlGlobalHistory.db")
                && file.artifact_kind == PrefetchArtifactKind::SuperfetchDatabase
        }));
        assert!(
            plan.files
                .iter()
                .all(|file| !file.file_name.eq_ignore_ascii_case("ignored.txt"))
        );
        Ok(())
    }
}
