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

const LNK_COLLECTION_SCHEMA: &str = "windows_lnk_collection_v1";
const LNK_COLLECTOR_NAME: &str = "windows_lnk";
const LNK_JSONL_NAME: &str = "lnk_manifest.jsonl";
const LOW_VALUE_PROFILE_NAMES: &[&str] = &[
    "all users",
    "default",
    "default user",
    "defaultapppool",
    "defaultuser0",
    "public",
];
#[cfg(target_os = "windows")]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

#[derive(Debug, Clone, Args)]
pub struct LnkCollectCli {
    #[arg(long, help = "NTFS volume, for example C:")]
    pub volume: String,

    #[arg(
        long = "out-dir",
        help = "Output root directory for collected LNK files"
    )]
    pub out_dir: PathBuf,

    #[arg(
        long,
        help = "Optional collection manifest path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_lnk/manifest.json"
    )]
    pub manifest: Option<PathBuf>,

    #[arg(
        long = "artifact-manifest",
        help = "Optional JSONL artifact manifest path; defaults to <out-dir>/<volume>/lnk_manifest.jsonl"
    )]
    pub artifact_manifest: Option<PathBuf>,

    #[arg(
        long = "collection-log",
        help = "Optional collection log path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_lnk/collection.log"
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
pub struct LnkCollectRequest {
    pub volume: String,
    pub out_dir: PathBuf,
    pub manifest: Option<PathBuf>,
    pub artifact_manifest: Option<PathBuf>,
    pub collection_log: Option<PathBuf>,
    pub diagnostic_log: Option<PathBuf>,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct LnkCollectSummary {
    pub volume: String,
    pub output_root: PathBuf,
    pub manifest_path: PathBuf,
    pub artifact_manifest_path: PathBuf,
    pub collection_log_path: PathBuf,
    pub staged_paths: Vec<PathBuf>,
    pub file_records: Vec<LnkCollectedFile>,
    pub failures: Vec<LnkCollectionFailure>,
}

#[derive(Debug, Clone)]
pub struct LnkProgress {
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
pub enum LnkArtifactLocation {
    Recent,
    OfficeRecent,
    Desktop,
    UserStartMenu,
    CommonStartMenu,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnkCollectedFile {
    pub archive_path: String,
    pub source_volume: String,
    pub source_path: String,
    pub destination_path: String,
    pub vss_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_username: Option<String>,
    pub artifact_location: LnkArtifactLocation,
    pub filename: String,
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
struct LnkArtifactManifestRecord {
    source_volume: String,
    source_path: String,
    destination_path: String,
    vss_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_username: Option<String>,
    artifact_location: LnkArtifactLocation,
    filename: String,
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

impl From<&LnkCollectedFile> for LnkArtifactManifestRecord {
    fn from(value: &LnkCollectedFile) -> Self {
        Self {
            source_volume: value.source_volume.clone(),
            source_path: value.source_path.clone(),
            destination_path: value.destination_path.clone(),
            vss_path: value.vss_path.clone(),
            profile_username: value.profile_username.clone(),
            artifact_location: value.artifact_location,
            filename: value.filename.clone(),
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
pub struct LnkCollectionFailure {
    pub source_path: String,
    pub vss_path: String,
    pub archive_path: String,
    pub operation: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LnkCollectionManifest {
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
    artifact_manifest_path: String,
    total_profiles_scanned: usize,
    total_profiles_skipped: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    privileges_enabled: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shadow_copy: Option<ShadowCopyMetadata>,
    total_files_found: usize,
    total_files_copied: usize,
    total_files_failed: usize,
    files: Vec<LnkCollectedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    failures: Vec<LnkCollectionFailure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct PlannedLnkFile {
    source_path: PathBuf,
    live_path: String,
    archive_path: PathBuf,
    profile_username: Option<String>,
    artifact_location: LnkArtifactLocation,
    filename: String,
}

struct LnkPlan {
    files: Vec<PlannedLnkFile>,
    warnings: Vec<String>,
    profiles_scanned: usize,
    profiles_skipped: usize,
}

pub fn run(args: &LnkCollectCli) -> Result<()> {
    let summary = collect(&LnkCollectRequest {
        volume: args.volume.clone(),
        out_dir: args.out_dir.clone(),
        manifest: args.manifest.clone(),
        artifact_manifest: args.artifact_manifest.clone(),
        collection_log: args.collection_log.clone(),
        diagnostic_log: args.diagnostic_log.clone(),
        elevate: args.elevate,
    })?;
    println!("Collected {} LNK files.", summary.file_records.len());
    println!("Failed {} LNK files.", summary.failures.len());
    println!(
        "Artifact manifest: {}",
        summary.artifact_manifest_path.display()
    );
    println!("Manifest: {}", summary.manifest_path.display());
    println!("Collection log: {}", summary.collection_log_path.display());
    Ok(())
}

pub fn collect(request: &LnkCollectRequest) -> Result<LnkCollectSummary> {
    let mut reporter = |_| {};
    collect_with_progress(request, &mut reporter)
}

pub fn collect_with_progress(
    request: &LnkCollectRequest,
    reporter: &mut dyn FnMut(LnkProgress),
) -> Result<LnkCollectSummary> {
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
        reporter(LnkProgress {
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
        .with_context(|| format!("delete LNK shadow copy {}", shadow_copy.id));
    match (result, delete_result) {
        (Ok(summary), Ok(())) => {
            mark_shadow_deleted(&summary.manifest_path)?;
            Ok(summary)
        }
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(delete_error)) => Err(error.context(format!(
            "also failed to delete LNK shadow copy {}: {delete_error:#}",
            shadow_copy.id
        ))),
    }
}

pub fn collect_with_progress_using_shadow_copy(
    request: &LnkCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    reporter: &mut dyn FnMut(LnkProgress),
) -> Result<LnkCollectSummary> {
    validate_request(request)?;
    collect_from_shadow_copy(request, shadow_copy, true, reporter)
}

pub fn default_manifest_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_manifest_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_LNK_COLLECTOR,
    )
}

pub fn default_artifact_manifest_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    Ok(output_root
        .join(volume_archive_root(volume)?)
        .join(LNK_JSONL_NAME))
}

pub fn default_collection_log_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_log_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_LNK_COLLECTOR,
    )
}

pub fn default_diagnostic_log_path(_output_root: &Path) -> PathBuf {
    runtime_support::technical_log_path()
}

fn validate_request(request: &LnkCollectRequest) -> Result<()> {
    let _ = usn_journal::normalize_volume(&request.volume)?;
    if request.out_dir.as_os_str().is_empty() {
        bail!("--out-dir must not be empty");
    }
    Ok(())
}

fn collect_from_shadow_copy(
    request: &LnkCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    shared_shadow_copy: bool,
    reporter: &mut dyn FnMut(LnkProgress),
) -> Result<LnkCollectSummary> {
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
    reporter(LnkProgress {
        progress_value: 0.05,
        detail: format!("Enumerating LNK files on {volume}."),
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
    let LnkPlan {
        files: planned,
        warnings: plan_warnings,
        profiles_scanned,
        profiles_skipped,
    } = plan_lnk_files(&volume, &source_root)?;
    warnings.extend(plan_warnings);
    let mut staged_paths = Vec::new();
    let mut file_records = Vec::new();
    let mut failures = Vec::new();
    let total = planned.len();

    for (index, planned_file) in planned.into_iter().enumerate() {
        let archive_name = normalize_archive_path_string(&planned_file.archive_path);
        let destination_path = request.out_dir.join(&planned_file.archive_path);
        reporter(LnkProgress {
            progress_value: 0.08 + (0.80 * progress_fraction(index, total)),
            detail: format!("Copying {archive_name}"),
            progress_text: format!("{index} / {total} LNK"),
        });
        match copy_lnk_file(&volume, &planned_file, &destination_path) {
            Ok(record) => {
                staged_paths.push(destination_path);
                file_records.push(record);
            }
            Err(error) => failures.push(LnkCollectionFailure {
                source_path: planned_file.live_path,
                vss_path: planned_file.source_path.display().to_string(),
                archive_path: archive_name,
                operation: "copy_hash_verify".to_string(),
                error: error.to_string(),
            }),
        }
    }

    reporter(LnkProgress {
        progress_value: 0.90,
        detail: "Writing LNK JSONL manifest.".to_string(),
        progress_text: "JSONL".to_string(),
    });
    write_artifact_manifest(&artifact_manifest_path, &file_records)?;
    staged_paths.push(artifact_manifest_path.clone());

    reporter(LnkProgress {
        progress_value: 0.94,
        detail: "Writing LNK manifest and collection log.".to_string(),
        progress_text: "Manifest".to_string(),
    });
    let end_time = Utc::now();
    let manifest = LnkCollectionManifest {
        metadata_schema: LNK_COLLECTION_SCHEMA.to_string(),
        artifact_type: "windows_lnk_collection".to_string(),
        artifact_name: "Windows LNK Files".to_string(),
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
            name: LNK_COLLECTOR_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            language: "rust".to_string(),
        },
        transaction_safe: true,
        source_root: source_root.display().to_string(),
        source_globs: lnk_source_globs(&volume),
        artifact_manifest_path: relative_output_path_string(
            &request.out_dir,
            &artifact_manifest_path,
        ),
        total_profiles_scanned: profiles_scanned,
        total_profiles_skipped: profiles_skipped,
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

    reporter(LnkProgress {
        progress_value: 1.0,
        detail: format!(
            "Copied {} of {} LNK files from {volume}.",
            file_records.len(),
            total
        ),
        progress_text: format!("{} copied, {} failed", file_records.len(), failures.len()),
    });

    Ok(LnkCollectSummary {
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
) -> Result<LnkCollectSummary> {
    let bytes = fs::read(manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let manifest: LnkCollectionManifest = serde_json::from_slice(&bytes)
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
    Ok(LnkCollectSummary {
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

fn plan_lnk_files(volume: &str, source_root: &Path) -> Result<LnkPlan> {
    let normalized_volume = usn_journal::normalize_volume(volume)?;
    let archive_root = volume_archive_root(&normalized_volume)?;
    let users_root = source_root.join("Users");
    let mut planned = Vec::new();
    let mut warnings = Vec::new();
    let mut archive_paths = BTreeSet::new();
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

            add_profile_lnk_roots(
                &profile_root,
                &archive_profile_root,
                &live_profile_root,
                &profile_name,
                &mut planned,
                &mut archive_paths,
                &mut warnings,
            )?;
        }
    } else {
        warnings.push(format!(
            "users directory was not present in snapshot: {}",
            users_root.display()
        ));
    }

    let common_start_menu = source_root
        .join("ProgramData")
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu");
    let common_archive = archive_root
        .join("ProgramData")
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu");
    let common_live = format!(
        r"{}\ProgramData\Microsoft\Windows\Start Menu",
        normalized_volume
    );
    add_lnk_directory(
        &common_start_menu,
        &common_archive,
        &common_live,
        None,
        LnkArtifactLocation::CommonStartMenu,
        true,
        &mut planned,
        &mut archive_paths,
        &mut warnings,
    )?;

    planned.sort_by_key(|file| file.archive_path.display().to_string().to_ascii_lowercase());
    Ok(LnkPlan {
        files: planned,
        warnings,
        profiles_scanned,
        profiles_skipped,
    })
}

fn add_profile_lnk_roots(
    profile_root: &Path,
    archive_profile_root: &Path,
    live_profile_root: &str,
    profile_name: &str,
    planned: &mut Vec<PlannedLnkFile>,
    archive_paths: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    for (relative_dir, artifact_location, recursive) in [
        (
            PathBuf::from(r"AppData\Roaming\Microsoft\Windows\Recent"),
            LnkArtifactLocation::Recent,
            false,
        ),
        (
            PathBuf::from(r"AppData\Roaming\Microsoft\Office\Recent"),
            LnkArtifactLocation::OfficeRecent,
            false,
        ),
        (
            PathBuf::from("Desktop"),
            LnkArtifactLocation::Desktop,
            false,
        ),
        (
            PathBuf::from(r"AppData\Roaming\Microsoft\Windows\Start Menu"),
            LnkArtifactLocation::UserStartMenu,
            true,
        ),
    ] {
        let source_dir = profile_root.join(&relative_dir);
        let archive_dir = archive_profile_root.join(&relative_dir);
        let live_dir = format!(
            r"{}\{}",
            live_profile_root,
            normalize_live_path_string(&relative_dir)
        );
        add_lnk_directory(
            &source_dir,
            &archive_dir,
            &live_dir,
            Some(profile_name),
            artifact_location,
            recursive,
            planned,
            archive_paths,
            warnings,
        )?;
    }

    Ok(())
}

fn add_lnk_directory(
    source_dir: &Path,
    archive_dir: &Path,
    live_dir: &str,
    profile_username: Option<&str>,
    artifact_location: LnkArtifactLocation,
    recursive: bool,
    planned: &mut Vec<PlannedLnkFile>,
    archive_paths: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    if !source_dir.exists() {
        return Ok(());
    }
    if !source_dir.is_dir() {
        warnings.push(format!("LNK root was not a directory: {live_dir}"));
        return Ok(());
    }
    if is_reparse_or_symlink(source_dir) {
        warnings.push(format!("skipped reparse/symlink LNK root: {live_dir}"));
        return Ok(());
    }

    collect_lnk_directory(
        source_dir,
        source_dir,
        archive_dir,
        live_dir,
        profile_username,
        artifact_location,
        recursive,
        planned,
        archive_paths,
        warnings,
    )
}

fn collect_lnk_directory(
    root_dir: &Path,
    current_dir: &Path,
    archive_root: &Path,
    live_root: &str,
    profile_username: Option<&str>,
    artifact_location: LnkArtifactLocation,
    recursive: bool,
    planned: &mut Vec<PlannedLnkFile>,
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
            if !recursive {
                continue;
            }
            if is_reparse_or_symlink(&source_path) {
                warnings.push(format!(
                    "skipped reparse/symlink directory: {}",
                    source_path.display()
                ));
                continue;
            }
            collect_lnk_directory(
                root_dir,
                &source_path,
                archive_root,
                live_root,
                profile_username,
                artifact_location,
                recursive,
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
                "skipped reparse/symlink LNK file: {}",
                source_path.display()
            ));
            continue;
        }

        let file_name = entry.file_name().to_string_lossy().to_string();
        if !matches_lnk_file(&file_name) {
            continue;
        }

        let Ok(relative_path) = source_path.strip_prefix(root_dir) else {
            warnings.push(format!(
                "could not derive relative LNK path for {}",
                source_path.display()
            ));
            continue;
        };
        let archive_path = archive_root.join(relative_path);
        let normalized_archive_path = normalize_archive_path_string(&archive_path);
        if !archive_paths.insert(normalized_archive_path) {
            continue;
        }

        planned.push(PlannedLnkFile {
            source_path: source_path.clone(),
            live_path: join_live_path(live_root, relative_path),
            archive_path,
            profile_username: profile_username.map(str::to_string),
            artifact_location,
            filename: file_name,
        });
    }

    Ok(())
}

fn matches_lnk_file(file_name: &str) -> bool {
    file_name.to_ascii_lowercase().ends_with(".lnk")
}

fn join_live_path(root: &str, relative_path: &Path) -> String {
    let relative = normalize_live_path_string(relative_path);
    if relative.is_empty() {
        root.to_string()
    } else {
        format!(r"{}\{}", root, relative)
    }
}

fn lnk_source_globs(volume: &str) -> Vec<String> {
    vec![
        format!(r"{volume}\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk"),
        format!(r"{volume}\Users\*\AppData\Roaming\Microsoft\Office\Recent\*.lnk"),
        format!(r"{volume}\Users\*\Desktop\*.lnk"),
        format!(r"{volume}\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\**\*.lnk"),
        format!(r"{volume}\ProgramData\Microsoft\Windows\Start Menu\**\*.lnk"),
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

fn is_low_value_profile_name(profile_name: &str) -> bool {
    LOW_VALUE_PROFILE_NAMES.contains(&profile_name.trim().to_ascii_lowercase().as_str())
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

fn copy_lnk_file(
    volume: &str,
    planned_file: &PlannedLnkFile,
    destination_path: &Path,
) -> Result<LnkCollectedFile> {
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create LNK destination directory {}", parent.display()))?;
    }
    let source_hash = sha256_file(&planned_file.source_path)
        .with_context(|| format!("hash source {}", planned_file.source_path.display()))?;
    fs::copy(&planned_file.source_path, destination_path).with_context(|| {
        format!(
            "copy LNK {} -> {}",
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
    Ok(LnkCollectedFile {
        archive_path: normalize_archive_path_string(&planned_file.archive_path),
        source_volume: usn_journal::normalize_volume(volume)?,
        source_path: planned_file.live_path.clone(),
        destination_path: normalize_archive_path_string(&planned_file.archive_path),
        vss_path: planned_file.source_path.display().to_string(),
        profile_username: planned_file.profile_username.clone(),
        artifact_location: planned_file.artifact_location,
        filename: planned_file.filename.clone(),
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

fn write_artifact_manifest(path: &Path, file_records: &[LnkCollectedFile]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "create LNK artifact manifest directory {}",
                parent.display()
            )
        })?;
    }
    let file = File::create(path)
        .with_context(|| format!("create LNK artifact manifest {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    for record in file_records {
        serde_json::to_writer(&mut writer, &LnkArtifactManifestRecord::from(record))?;
        writer.write_all(b"\n")?;
    }
    writer.flush().context("flush LNK artifact manifest")
}

fn write_manifest(path: &Path, manifest: &LnkCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create manifest directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(manifest)?;
    fs::write(path, bytes).with_context(|| format!("write manifest {}", path.display()))
}

fn write_collection_log(path: &Path, manifest: &LnkCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create collection log directory {}", parent.display()))?;
    }
    let file = File::create(path).with_context(|| format!("create log {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "lnk collection volume={}", manifest.volume)?;
    writeln!(writer, "source_root={}", manifest.source_root)?;
    writeln!(
        writer,
        "artifact_manifest={}",
        manifest.artifact_manifest_path
    )?;
    writeln!(
        writer,
        "profiles_scanned={} profiles_skipped={}",
        manifest.total_profiles_scanned, manifest.total_profiles_skipped
    )?;
    writeln!(
        writer,
        "found={} copied={} failed={}",
        manifest.total_files_found, manifest.total_files_copied, manifest.total_files_failed
    )?;
    for entry in &manifest.files {
        writeln!(
            writer,
            "copied {} size={} sha256={} location={}",
            entry.archive_path,
            entry.file_size,
            entry.sha256,
            lnk_location_name(entry.artifact_location)
        )?;
    }
    for failure in &manifest.failures {
        writeln!(
            writer,
            "failed {} operation={} error={}",
            failure.archive_path, failure.operation, failure.error
        )?;
    }
    writer.flush().context("flush LNK collection log")
}

fn lnk_location_name(location: LnkArtifactLocation) -> &'static str {
    match location {
        LnkArtifactLocation::Recent => "recent",
        LnkArtifactLocation::OfficeRecent => "office_recent",
        LnkArtifactLocation::Desktop => "desktop",
        LnkArtifactLocation::UserStartMenu => "user_start_menu",
        LnkArtifactLocation::CommonStartMenu => "common_start_menu",
    }
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
fn relaunch_elevated(request: &LnkCollectRequest) -> Result<()> {
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

    unsafe { ShellExecuteExW(&mut execute) }.context("launch elevated LNK collector via UAC")?;
    if execute.hProcess.is_invalid() {
        bail!("UAC launch did not return a process handle to wait on");
    }

    unsafe {
        WaitForSingleObject(execute.hProcess, INFINITE);
    }
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(execute.hProcess, &mut exit_code) }
        .context("read elevated LNK collector exit code")?;
    let _ = unsafe { CloseHandle(execute.hProcess) };
    if exit_code != 0 {
        bail!("elevated LNK collector exited with status {exit_code}");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn relaunch_elevated(_request: &LnkCollectRequest) -> Result<()> {
    bail!("LNK elevation relaunch is only available on Windows")
}

fn build_relaunch_parameters(request: &LnkCollectRequest) -> String {
    let mut values = vec![
        "collect-lnk".to_string(),
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
    use std::path::PathBuf;

    use anyhow::Result;
    use tempfile::tempdir;

    use super::{
        LnkArtifactLocation, default_artifact_manifest_path, default_collection_log_path,
        default_manifest_path, plan_lnk_files,
    };

    #[test]
    fn default_lnk_metadata_paths_live_under_expected_roots() -> Result<()> {
        let root = PathBuf::from(r"C:\evidence");
        assert_eq!(
            default_manifest_path(&root, "c:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_lnk")
                .join("manifest.json")
        );
        assert_eq!(
            default_collection_log_path(&root, r"\\?\C:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_lnk")
                .join("collection.log")
        );
        assert_eq!(
            default_artifact_manifest_path(&root, "c:")?,
            root.join("C").join("lnk_manifest.jsonl")
        );
        Ok(())
    }

    #[test]
    fn plan_lnk_files_collects_expected_roots_and_skips_low_value_profiles() -> Result<()> {
        let temp = tempdir()?;
        let source_root = temp.path().join("shadow");
        let alice_root = source_root.join("Users").join("alice");
        let recent = alice_root
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("Recent");
        let office_recent = alice_root
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Office")
            .join("Recent");
        let desktop = alice_root.join("Desktop");
        let start_menu = alice_root
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Case Tools");
        let public_recent = source_root
            .join("Users")
            .join("Public")
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("Recent");
        let common_start_menu = source_root
            .join("ProgramData")
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Common");

        fs::create_dir_all(&recent)?;
        fs::create_dir_all(&office_recent)?;
        fs::create_dir_all(&desktop)?;
        fs::create_dir_all(&start_menu)?;
        fs::create_dir_all(&public_recent)?;
        fs::create_dir_all(&common_start_menu)?;
        fs::write(recent.join("recent-doc.lnk"), b"recent")?;
        fs::write(office_recent.join("office-doc.lnk"), b"office")?;
        fs::write(desktop.join("desktop-tool.LNK"), b"desktop")?;
        fs::write(start_menu.join("case-tool.lnk"), b"start-menu")?;
        fs::write(common_start_menu.join("common-tool.lnk"), b"common-start")?;
        fs::write(recent.join("ignore.txt"), b"ignore")?;
        fs::write(public_recent.join("skip-me.lnk"), b"skip")?;

        let planned = plan_lnk_files("c:", &source_root)?;

        assert_eq!(planned.files.len(), 5);
        assert_eq!(planned.profiles_scanned, 2);
        assert_eq!(planned.profiles_skipped, 1);
        assert!(planned.files.iter().any(|file| {
            file.artifact_location == LnkArtifactLocation::Recent
                && file.profile_username.as_deref() == Some("alice")
                && file.archive_path
                    == PathBuf::from("C")
                        .join("Users")
                        .join("alice")
                        .join("AppData")
                        .join("Roaming")
                        .join("Microsoft")
                        .join("Windows")
                        .join("Recent")
                        .join("recent-doc.lnk")
        }));
        assert!(planned.files.iter().any(|file| {
            file.artifact_location == LnkArtifactLocation::OfficeRecent
                && file.profile_username.as_deref() == Some("alice")
                && file.filename == "office-doc.lnk"
        }));
        assert!(planned.files.iter().any(|file| {
            file.artifact_location == LnkArtifactLocation::Desktop
                && file.profile_username.as_deref() == Some("alice")
                && file.filename == "desktop-tool.LNK"
        }));
        assert!(planned.files.iter().any(|file| {
            file.artifact_location == LnkArtifactLocation::UserStartMenu
                && file.profile_username.as_deref() == Some("alice")
                && file.archive_path
                    == PathBuf::from("C")
                        .join("Users")
                        .join("alice")
                        .join("AppData")
                        .join("Roaming")
                        .join("Microsoft")
                        .join("Windows")
                        .join("Start Menu")
                        .join("Programs")
                        .join("Case Tools")
                        .join("case-tool.lnk")
        }));
        assert!(planned.files.iter().any(|file| {
            file.artifact_location == LnkArtifactLocation::CommonStartMenu
                && file.profile_username.is_none()
                && file.archive_path
                    == PathBuf::from("C")
                        .join("ProgramData")
                        .join("Microsoft")
                        .join("Windows")
                        .join("Start Menu")
                        .join("Programs")
                        .join("Common")
                        .join("common-tool.lnk")
        }));
        Ok(())
    }
}
