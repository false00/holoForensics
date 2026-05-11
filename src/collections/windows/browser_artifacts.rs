#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::collection_metadata;
use crate::collections::windows::{usn_journal, vss};
use crate::runtime_support;

const BROWSER_ARTIFACTS_COLLECTION_SCHEMA: &str = "windows_browser_artifacts_collection_v1";
const BROWSER_ARTIFACTS_COLLECTOR_NAME: &str = "windows_browser_artifacts";

#[derive(Debug, Clone, Args)]
pub struct BrowserArtifactsCollectCli {
    #[arg(long, help = "NTFS volume, for example C:")]
    pub volume: String,

    #[arg(
        long = "out-dir",
        help = "Output root directory for collected browser artifacts"
    )]
    pub out_dir: PathBuf,

    #[arg(
        long,
        help = "Optional collection manifest path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_browser_artifacts/manifest.json"
    )]
    pub manifest: Option<PathBuf>,

    #[arg(
        long = "collection-log",
        help = "Optional collection log path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_browser_artifacts/collection.log"
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
pub struct BrowserArtifactsCollectRequest {
    pub volume: String,
    pub out_dir: PathBuf,
    pub manifest: Option<PathBuf>,
    pub collection_log: Option<PathBuf>,
    pub diagnostic_log: Option<PathBuf>,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct BrowserArtifactsCollectSummary {
    pub volume: String,
    pub output_root: PathBuf,
    pub manifest_path: PathBuf,
    pub collection_log_path: PathBuf,
    pub staged_paths: Vec<PathBuf>,
    pub file_records: Vec<BrowserArtifactsCollectedFile>,
    pub failures: Vec<BrowserArtifactsCollectionFailure>,
}

#[derive(Debug, Clone)]
pub struct BrowserArtifactsProgress {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserArtifactsCollectedFile {
    pub archive_path: String,
    pub live_path: String,
    pub vss_path: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessed_utc: Option<String>,
    pub source_sha256: String,
    pub sha256: String,
    pub copy_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserArtifactsCollectionFailure {
    pub live_path: String,
    pub vss_path: String,
    pub archive_path: String,
    pub operation: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserArtifactsCollectionManifest {
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
    files: Vec<BrowserArtifactsCollectedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    failures: Vec<BrowserArtifactsCollectionFailure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct PlannedBrowserArtifactFile {
    source_path: PathBuf,
    live_path: String,
    archive_path: PathBuf,
}

struct BrowserArtifactPlan {
    files: Vec<PlannedBrowserArtifactFile>,
    warnings: Vec<String>,
}

pub fn run(args: &BrowserArtifactsCollectCli) -> Result<()> {
    let summary = collect(&BrowserArtifactsCollectRequest {
        volume: args.volume.clone(),
        out_dir: args.out_dir.clone(),
        manifest: args.manifest.clone(),
        collection_log: args.collection_log.clone(),
        diagnostic_log: args.diagnostic_log.clone(),
        elevate: args.elevate,
    })?;
    println!(
        "Collected {} browser artifact files.",
        summary.file_records.len()
    );
    println!("Failed {} browser artifact files.", summary.failures.len());
    println!("Manifest: {}", summary.manifest_path.display());
    println!("Collection log: {}", summary.collection_log_path.display());
    Ok(())
}

pub fn collect(request: &BrowserArtifactsCollectRequest) -> Result<BrowserArtifactsCollectSummary> {
    let mut reporter = |_| {};
    collect_with_progress(request, &mut reporter)
}

pub fn collect_with_progress(
    request: &BrowserArtifactsCollectRequest,
    reporter: &mut dyn FnMut(BrowserArtifactsProgress),
) -> Result<BrowserArtifactsCollectSummary> {
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
        reporter(BrowserArtifactsProgress {
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
        .with_context(|| format!("delete browser artifacts shadow copy {}", shadow_copy.id));
    match (result, delete_result) {
        (Ok(summary), Ok(())) => {
            mark_shadow_deleted(&summary.manifest_path)?;
            Ok(summary)
        }
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(delete_error)) => Err(error.context(format!(
            "also failed to delete browser artifacts shadow copy {}: {delete_error:#}",
            shadow_copy.id
        ))),
    }
}

pub fn collect_with_progress_using_shadow_copy(
    request: &BrowserArtifactsCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    reporter: &mut dyn FnMut(BrowserArtifactsProgress),
) -> Result<BrowserArtifactsCollectSummary> {
    validate_request(request)?;
    collect_from_shadow_copy(request, shadow_copy, true, reporter)
}

pub fn default_manifest_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_manifest_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_BROWSER_ARTIFACTS_COLLECTOR,
    )
}

pub fn default_collection_log_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_log_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_BROWSER_ARTIFACTS_COLLECTOR,
    )
}

pub fn default_diagnostic_log_path(_output_root: &Path) -> PathBuf {
    runtime_support::technical_log_path()
}

fn validate_request(request: &BrowserArtifactsCollectRequest) -> Result<()> {
    let _ = usn_journal::normalize_volume(&request.volume)?;
    if request.out_dir.as_os_str().is_empty() {
        bail!("--out-dir must not be empty");
    }
    Ok(())
}

fn collect_from_shadow_copy(
    request: &BrowserArtifactsCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    shared_shadow_copy: bool,
    reporter: &mut dyn FnMut(BrowserArtifactsProgress),
) -> Result<BrowserArtifactsCollectSummary> {
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
    reporter(BrowserArtifactsProgress {
        progress_value: 0.05,
        detail: format!("Enumerating browser artifact files on {volume}."),
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
    let plan = plan_browser_artifact_files(&volume, &source_root)?;
    warnings.extend(plan.warnings);
    let planned = plan.files;
    let mut staged_paths = Vec::new();
    let mut file_records = Vec::new();
    let mut failures = Vec::new();
    let total = planned.len();

    for (index, planned_file) in planned.into_iter().enumerate() {
        let archive_name = normalize_archive_path_string(&planned_file.archive_path);
        let destination_path = request.out_dir.join(&planned_file.archive_path);
        reporter(BrowserArtifactsProgress {
            progress_value: 0.08 + (0.82 * progress_fraction(index, total)),
            detail: format!("Copying {archive_name}"),
            progress_text: format!("{index} / {total} browser artifacts"),
        });
        match copy_browser_artifact_file(&planned_file, &destination_path) {
            Ok(record) => {
                staged_paths.push(destination_path);
                file_records.push(record);
            }
            Err(error) => failures.push(BrowserArtifactsCollectionFailure {
                live_path: planned_file.live_path,
                vss_path: planned_file.source_path.display().to_string(),
                archive_path: archive_name,
                operation: "copy_hash_verify".to_string(),
                error: error.to_string(),
            }),
        }
    }

    reporter(BrowserArtifactsProgress {
        progress_value: 0.94,
        detail: "Writing browser artifacts manifest and collection log.".to_string(),
        progress_text: "Manifest".to_string(),
    });
    let end_time = Utc::now();
    let manifest = BrowserArtifactsCollectionManifest {
        metadata_schema: BROWSER_ARTIFACTS_COLLECTION_SCHEMA.to_string(),
        artifact_type: "windows_browser_artifacts_collection".to_string(),
        artifact_name: "Windows browser artifacts".to_string(),
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
            name: BROWSER_ARTIFACTS_COLLECTOR_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            language: "rust".to_string(),
        },
        transaction_safe: true,
        source_root: source_root.display().to_string(),
        source_globs: browser_source_globs(&volume),
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

    reporter(BrowserArtifactsProgress {
        progress_value: 1.0,
        detail: format!(
            "Copied {} of {} browser artifact files from {volume}.",
            file_records.len(),
            total
        ),
        progress_text: format!("{} copied, {} failed", file_records.len(), failures.len()),
    });

    Ok(BrowserArtifactsCollectSummary {
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
) -> Result<BrowserArtifactsCollectSummary> {
    let bytes = fs::read(manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let manifest: BrowserArtifactsCollectionManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode manifest {}", manifest_path.display()))?;
    let mut staged_paths = manifest
        .files
        .iter()
        .map(|record| output_root.join(record.archive_path.replace('/', "\\")))
        .collect::<Vec<_>>();
    staged_paths.push(manifest_path.to_path_buf());
    staged_paths.push(collection_log_path.to_path_buf());
    Ok(BrowserArtifactsCollectSummary {
        volume: volume.to_string(),
        output_root: output_root.to_path_buf(),
        manifest_path: manifest_path.to_path_buf(),
        collection_log_path: collection_log_path.to_path_buf(),
        staged_paths,
        file_records: manifest.files,
        failures: manifest.failures,
    })
}

fn plan_browser_artifact_files(volume: &str, source_root: &Path) -> Result<BrowserArtifactPlan> {
    let normalized_volume = usn_journal::normalize_volume(volume)?;
    let archive_root = volume_archive_root(&normalized_volume)?;
    let mut planned = Vec::new();
    let mut warnings = Vec::new();
    let mut archive_paths = BTreeSet::new();
    let users_root = source_root.join("Users");

    if users_root.exists() {
        for entry in fs::read_dir(&users_root)
            .with_context(|| format!("read users directory {}", users_root.display()))?
        {
            let entry = entry.with_context(|| format!("read entry in {}", users_root.display()))?;
            let user_root = entry.path();
            if !user_root.is_dir() || is_symlink(&user_root) {
                continue;
            }
            let user_name = entry.file_name();
            let user_archive_root = archive_root.join("Users").join(&user_name);
            let live_user_root = format!(
                r"{}\Users\{}",
                normalized_volume,
                user_name.to_string_lossy()
            );

            add_chromium_user_data(
                &user_root,
                &user_archive_root,
                &live_user_root,
                Path::new(r"AppData\Local\Google\Chrome\User Data"),
                &mut planned,
                &mut archive_paths,
                &mut warnings,
            )?;
            add_chromium_user_data(
                &user_root,
                &user_archive_root,
                &live_user_root,
                Path::new(r"AppData\Local\Microsoft\Edge\User Data"),
                &mut planned,
                &mut archive_paths,
                &mut warnings,
            )?;

            for relative_root in [
                PathBuf::from(r"AppData\Roaming\Mozilla\Firefox"),
                PathBuf::from(r"AppData\Local\Mozilla\Firefox"),
                PathBuf::from(r"AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"),
                PathBuf::from(r"AppData\Local\Microsoft\Windows\WebCache"),
                PathBuf::from(r"AppData\Local\Microsoft\Windows\INetCache"),
                PathBuf::from(r"AppData\Local\Microsoft\Windows\INetCookies"),
                PathBuf::from(r"AppData\Roaming\Microsoft\Protect"),
                PathBuf::from(r"AppData\Roaming\Microsoft\Credentials"),
                PathBuf::from(r"AppData\Local\Microsoft\Credentials"),
            ] {
                let source_dir = user_root.join(&relative_root);
                let archive_dir = user_archive_root.join(&relative_root);
                let live_dir = format!(
                    r"{}\{}",
                    live_user_root,
                    normalize_live_path_string(&relative_root)
                );
                add_recursive_files(
                    &source_dir,
                    &archive_dir,
                    &live_dir,
                    &mut planned,
                    &mut archive_paths,
                    &mut warnings,
                )?;
            }

            for file_name in ["NTUSER.DAT"] {
                add_optional_file(
                    &user_root.join(file_name),
                    &user_archive_root.join(file_name),
                    &format!(r"{live_user_root}\{file_name}"),
                    &mut planned,
                    &mut archive_paths,
                );
            }
            for entry in fs::read_dir(&user_root)
                .with_context(|| format!("read user root {}", user_root.display()))?
            {
                let entry =
                    entry.with_context(|| format!("read entry in {}", user_root.display()))?;
                let source_path = entry.path();
                if !source_path.is_file() {
                    continue;
                }
                let file_name = entry.file_name();
                let file_name_text = file_name.to_string_lossy();
                if file_name_text
                    .to_ascii_lowercase()
                    .starts_with("ntuser.dat.log")
                {
                    add_optional_file(
                        &source_path,
                        &user_archive_root.join(&file_name),
                        &format!(r"{live_user_root}\{file_name_text}"),
                        &mut planned,
                        &mut archive_paths,
                    );
                }
            }
        }
    } else {
        warnings.push(format!(
            "users directory was not present in snapshot: {}",
            users_root.display()
        ));
    }

    for hive in ["SYSTEM", "SECURITY", "SOFTWARE"] {
        let source_path = source_root
            .join("Windows")
            .join("System32")
            .join("config")
            .join(hive);
        add_required_file(
            source_path,
            archive_root
                .join("Windows")
                .join("System32")
                .join("config")
                .join(hive),
            format!(r"{normalized_volume}\Windows\System32\config\{hive}"),
            &mut planned,
            &mut archive_paths,
        );
    }
    add_recursive_files(
        &source_root
            .join("Windows")
            .join("System32")
            .join("Microsoft")
            .join("Protect"),
        &archive_root
            .join("Windows")
            .join("System32")
            .join("Microsoft")
            .join("Protect"),
        &format!(r"{normalized_volume}\Windows\System32\Microsoft\Protect"),
        &mut planned,
        &mut archive_paths,
        &mut warnings,
    )?;

    planned.sort_by_key(|file| file.archive_path.display().to_string().to_ascii_lowercase());
    Ok(BrowserArtifactPlan {
        files: planned,
        warnings,
    })
}

fn add_chromium_user_data(
    user_root: &Path,
    user_archive_root: &Path,
    live_user_root: &str,
    relative_user_data: &Path,
    planned: &mut Vec<PlannedBrowserArtifactFile>,
    archive_paths: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let source_user_data = user_root.join(relative_user_data);
    let archive_user_data = user_archive_root.join(relative_user_data);
    let live_user_data = format!(
        r"{}\{}",
        live_user_root,
        normalize_live_path_string(relative_user_data)
    );
    if !source_user_data.exists() {
        warnings.push(format!(
            "optional browser artifact root not found: {live_user_data}"
        ));
        return Ok(());
    }
    if !source_user_data.is_dir() {
        warnings.push(format!(
            "browser artifact root was not a directory: {live_user_data}"
        ));
        return Ok(());
    }
    if is_symlink(&source_user_data) {
        warnings.push(format!(
            "skipped reparse/symlink browser artifact root: {live_user_data}"
        ));
        return Ok(());
    }

    for root_file in ["Local State", "First Run", "Last Version"] {
        add_optional_file(
            &source_user_data.join(root_file),
            &archive_user_data.join(root_file),
            &format!(r"{live_user_data}\{root_file}"),
            planned,
            archive_paths,
        );
    }

    for entry in fs::read_dir(&source_user_data)
        .with_context(|| format!("read Chromium user data {}", source_user_data.display()))?
    {
        let entry =
            entry.with_context(|| format!("read entry in {}", source_user_data.display()))?;
        let profile_path = entry.path();
        if !profile_path.is_dir() || is_symlink(&profile_path) {
            continue;
        }
        let profile_name = entry.file_name();
        let profile_name_text = profile_name.to_string_lossy();
        let archive_profile = archive_user_data.join(&profile_name);
        let live_profile = format!(r"{live_user_data}\{profile_name_text}");

        add_chromium_profile_files(
            &profile_path,
            &archive_profile,
            &live_profile,
            planned,
            archive_paths,
            warnings,
        )?;
    }

    Ok(())
}

fn add_chromium_profile_files(
    profile_path: &Path,
    archive_profile: &Path,
    live_profile: &str,
    planned: &mut Vec<PlannedBrowserArtifactFile>,
    archive_paths: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    for file_name in [
        "History",
        "Archived History",
        "History Provider Cache",
        "Cookies",
        "Web Data",
        "Login Data",
        "Login Data For Account",
        "Bookmarks",
        "Bookmarks.bak",
        "Preferences",
        "Secure Preferences",
        "Favicons",
        "Top Sites",
        "Shortcuts",
        "Visited Links",
        "Current Session",
        "Current Tabs",
        "Last Session",
        "Last Tabs",
        "Network Action Predictor",
        "Network Persistent State",
        "Reporting and NEL",
        "TransportSecurity",
        "Trust Tokens",
        "DIPS",
        "QuotaManager",
    ] {
        add_sqlite_family_files(
            profile_path,
            archive_profile,
            live_profile,
            Path::new(file_name),
            planned,
            archive_paths,
        )?;
    }

    for network_file in ["Cookies"] {
        add_sqlite_family_files(
            profile_path,
            archive_profile,
            live_profile,
            Path::new("Network").join(network_file).as_path(),
            planned,
            archive_paths,
        )?;
    }

    for relative_dir in [
        PathBuf::from("Sessions"),
        PathBuf::from("Local Storage"),
        PathBuf::from("Session Storage"),
        PathBuf::from("IndexedDB"),
        PathBuf::from("File System"),
        PathBuf::from("Storage"),
        PathBuf::from("databases"),
        PathBuf::from("Service Worker"),
        PathBuf::from("Extension State"),
        PathBuf::from("Local Extension Settings"),
        PathBuf::from("Sync Extension Settings"),
    ] {
        add_recursive_files(
            &profile_path.join(&relative_dir),
            &archive_profile.join(&relative_dir),
            &format!(
                r"{live_profile}\{}",
                normalize_live_path_string(&relative_dir)
            ),
            planned,
            archive_paths,
            warnings,
        )?;
    }

    add_chromium_extension_manifests(
        profile_path,
        archive_profile,
        live_profile,
        planned,
        archive_paths,
        warnings,
    )?;

    Ok(())
}

fn add_sqlite_family_files(
    base_path: &Path,
    archive_base: &Path,
    live_base: &str,
    relative_file: &Path,
    planned: &mut Vec<PlannedBrowserArtifactFile>,
    archive_paths: &mut BTreeSet<String>,
) -> Result<()> {
    let parent_relative = relative_file.parent().unwrap_or_else(|| Path::new(""));
    let file_name = relative_file
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("targeted browser artifact path has no file name"))?;
    let source_parent = base_path.join(parent_relative);
    if !source_parent.is_dir() {
        return Ok(());
    }
    let file_name_lower = file_name.to_string_lossy().to_ascii_lowercase();
    for entry in fs::read_dir(&source_parent).with_context(|| {
        format!(
            "read browser artifact directory {}",
            source_parent.display()
        )
    })? {
        let entry = entry.with_context(|| format!("read entry in {}", source_parent.display()))?;
        let source_path = entry.path();
        if !source_path.is_file() {
            continue;
        }
        let candidate_name = entry.file_name();
        let candidate_lower = candidate_name.to_string_lossy().to_ascii_lowercase();
        if candidate_lower == file_name_lower
            || candidate_lower.starts_with(&format!("{file_name_lower}-"))
        {
            let archive_path = archive_base.join(parent_relative).join(&candidate_name);
            let live_path = if parent_relative.as_os_str().is_empty() {
                format!(r"{live_base}\{}", candidate_name.to_string_lossy())
            } else {
                format!(
                    r"{}\{}\{}",
                    live_base,
                    normalize_live_path_string(parent_relative),
                    candidate_name.to_string_lossy()
                )
            };
            add_optional_file(
                &source_path,
                &archive_path,
                &live_path,
                planned,
                archive_paths,
            );
        }
    }
    Ok(())
}

fn add_chromium_extension_manifests(
    profile_path: &Path,
    archive_profile: &Path,
    live_profile: &str,
    planned: &mut Vec<PlannedBrowserArtifactFile>,
    archive_paths: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let extensions_root = profile_path.join("Extensions");
    if !extensions_root.exists() {
        return Ok(());
    }
    if !extensions_root.is_dir() || is_symlink(&extensions_root) {
        warnings.push(format!(
            "skipped non-directory or reparse/symlink extensions root: {live_profile}\\Extensions"
        ));
        return Ok(());
    }
    for extension_entry in fs::read_dir(&extensions_root)
        .with_context(|| format!("read extensions root {}", extensions_root.display()))?
    {
        let extension_entry = extension_entry
            .with_context(|| format!("read entry in {}", extensions_root.display()))?;
        let extension_path = extension_entry.path();
        if !extension_path.is_dir() || is_symlink(&extension_path) {
            continue;
        }
        let extension_id = extension_entry.file_name();
        for version_entry in fs::read_dir(&extension_path)
            .with_context(|| format!("read extension directory {}", extension_path.display()))?
        {
            let version_entry = version_entry
                .with_context(|| format!("read entry in {}", extension_path.display()))?;
            let version_path = version_entry.path();
            if !version_path.is_dir() || is_symlink(&version_path) {
                continue;
            }
            let version = version_entry.file_name();
            let source_path = version_path.join("manifest.json");
            let archive_path = archive_profile
                .join("Extensions")
                .join(&extension_id)
                .join(&version)
                .join("manifest.json");
            let live_path = format!(
                r"{}\Extensions\{}\{}\manifest.json",
                live_profile,
                extension_id.to_string_lossy(),
                version.to_string_lossy()
            );
            add_optional_file(
                &source_path,
                &archive_path,
                &live_path,
                planned,
                archive_paths,
            );
        }
    }
    Ok(())
}

fn add_recursive_files(
    source_dir: &Path,
    archive_dir: &Path,
    live_dir: &str,
    planned: &mut Vec<PlannedBrowserArtifactFile>,
    archive_paths: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    if !source_dir.exists() {
        warnings.push(format!(
            "optional browser artifact root not found: {live_dir}"
        ));
        return Ok(());
    }
    if !source_dir.is_dir() {
        warnings.push(format!(
            "browser artifact root was not a directory: {live_dir}"
        ));
        return Ok(());
    }
    if is_symlink(source_dir) {
        warnings.push(format!(
            "skipped reparse/symlink browser artifact root: {live_dir}"
        ));
        return Ok(());
    }

    for entry in fs::read_dir(source_dir)
        .with_context(|| format!("read browser artifact directory {}", source_dir.display()))?
    {
        let entry = entry.with_context(|| format!("read entry in {}", source_dir.display()))?;
        let source_path = entry.path();
        let file_name = entry.file_name();
        let archive_path = archive_dir.join(&file_name);
        let live_path = format!(r"{live_dir}\{}", file_name.to_string_lossy());
        if is_symlink(&source_path) {
            warnings.push(format!(
                "skipped reparse/symlink browser artifact path: {live_path}"
            ));
            continue;
        }
        if source_path.is_dir() {
            add_recursive_files(
                &source_path,
                &archive_path,
                &live_path,
                planned,
                archive_paths,
                warnings,
            )?;
        } else if source_path.is_file() {
            add_optional_file(
                &source_path,
                &archive_path,
                &live_path,
                planned,
                archive_paths,
            );
        }
    }
    Ok(())
}

fn add_optional_file(
    source_path: &Path,
    archive_path: &Path,
    live_path: &str,
    planned: &mut Vec<PlannedBrowserArtifactFile>,
    archive_paths: &mut BTreeSet<String>,
) {
    if source_path.is_file() {
        add_required_file(
            source_path.to_path_buf(),
            archive_path.to_path_buf(),
            live_path.to_string(),
            planned,
            archive_paths,
        );
    }
}

fn add_required_file(
    source_path: PathBuf,
    archive_path: PathBuf,
    live_path: String,
    planned: &mut Vec<PlannedBrowserArtifactFile>,
    archive_paths: &mut BTreeSet<String>,
) {
    if archive_paths.insert(normalize_archive_path_string(&archive_path)) {
        planned.push(PlannedBrowserArtifactFile {
            source_path,
            live_path,
            archive_path,
        });
    }
}

fn browser_source_globs(volume: &str) -> Vec<String> {
    vec![
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\History*"),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Archived History*"
        ),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Network\\Cookies*"
        ),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Cookies*"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Web Data*"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Login Data*"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Bookmarks*"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Preferences"),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Secure Preferences"
        ),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Favicons*"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Top Sites*"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Shortcuts*"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Visited Links"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Sessions\\"),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Local Storage\\"
        ),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Session Storage\\"
        ),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\IndexedDB\\"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\File System\\"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Storage\\"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\databases\\"),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Service Worker\\"
        ),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Extensions\\*\\*\\manifest.json"
        ),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Extension State\\"
        ),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Local Extension Settings\\"
        ),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Sync Extension Settings\\"
        ),
        format!("{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\History*"),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\Network\\Cookies*"
        ),
        format!("{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\Cookies*"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\Web Data*"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\Login Data*"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\Bookmarks*"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\Sessions\\"),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\Local Storage\\"
        ),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\Session Storage\\"
        ),
        format!("{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\IndexedDB\\"),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\Extensions\\*\\*\\manifest.json"
        ),
        format!("{volume}\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Mozilla\\Firefox\\"),
        format!(
            "{volume}\\Users\\*\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\"
        ),
        format!("{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\"),
        format!("{volume}\\Users\\*\\AppData\\Roaming\\Microsoft\\Protect\\"),
        format!("{volume}\\Users\\*\\AppData\\Roaming\\Microsoft\\Credentials\\"),
        format!("{volume}\\Users\\*\\AppData\\Local\\Microsoft\\Credentials\\"),
        format!(r"{volume}\Users\*\NTUSER.DAT"),
        format!(r"{volume}\Users\*\ntuser.dat.LOG*"),
        format!(r"{volume}\Windows\System32\config\SYSTEM"),
        format!(r"{volume}\Windows\System32\config\SECURITY"),
        format!(r"{volume}\Windows\System32\config\SOFTWARE"),
        format!("{volume}\\Windows\\System32\\Microsoft\\Protect\\"),
    ]
}

fn normalize_live_path_string(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("\\")
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn copy_browser_artifact_file(
    planned_file: &PlannedBrowserArtifactFile,
    destination_path: &Path,
) -> Result<BrowserArtifactsCollectedFile> {
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "create browser artifacts destination directory {}",
                parent.display()
            )
        })?;
    }
    let source_hash = sha256_file(&planned_file.source_path)
        .with_context(|| format!("hash source {}", planned_file.source_path.display()))?;
    fs::copy(&planned_file.source_path, destination_path).with_context(|| {
        format!(
            "copy browser artifacts {} -> {}",
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
    Ok(BrowserArtifactsCollectedFile {
        archive_path: normalize_archive_path_string(&planned_file.archive_path),
        live_path: planned_file.live_path.clone(),
        vss_path: planned_file.source_path.display().to_string(),
        size: metadata.len(),
        created_utc: system_time_utc(metadata.created().ok()),
        modified_utc: system_time_utc(metadata.modified().ok()),
        accessed_utc: system_time_utc(metadata.accessed().ok()),
        source_sha256: source_hash.clone(),
        sha256: destination_hash,
        copy_status: "success".to_string(),
    })
}

fn write_manifest(path: &Path, manifest: &BrowserArtifactsCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create manifest directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(manifest)?;
    fs::write(path, bytes).with_context(|| format!("write manifest {}", path.display()))
}

fn write_collection_log(path: &Path, manifest: &BrowserArtifactsCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create collection log directory {}", parent.display()))?;
    }
    let file = File::create(path).with_context(|| format!("create log {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writeln!(
        writer,
        "browser_artifacts collection volume={}",
        manifest.volume
    )?;
    writeln!(writer, "source_root={}", manifest.source_root)?;
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
    writer
        .flush()
        .context("flush browser artifacts collection log")
}

fn mark_shadow_deleted(_manifest_path: &Path) -> Result<()> {
    let bytes = fs::read(_manifest_path)
        .with_context(|| format!("read manifest {}", _manifest_path.display()))?;
    let mut manifest: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode manifest {}", _manifest_path.display()))?;
    if let Some(shadow_copy) = manifest
        .get_mut("shadow_copy")
        .and_then(serde_json::Value::as_object_mut)
    {
        shadow_copy.insert("deleted".to_string(), serde_json::Value::Bool(true));
    }
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    fs::write(_manifest_path, bytes)
        .with_context(|| format!("write manifest {}", _manifest_path.display()))
}

fn volume_archive_root(volume: &str) -> Result<PathBuf> {
    let normalized = usn_journal::normalize_volume(volume)?;
    Ok(PathBuf::from(normalized.trim_end_matches(':')))
}

fn extension_equals(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case(expected))
        .unwrap_or(false)
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
fn relaunch_elevated(request: &BrowserArtifactsCollectRequest) -> Result<()> {
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
        .context("launch elevated browser artifacts collector via UAC")?;
    if execute.hProcess.is_invalid() {
        bail!("UAC launch did not return a process handle to wait on");
    }

    unsafe {
        WaitForSingleObject(execute.hProcess, INFINITE);
    }
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(execute.hProcess, &mut exit_code) }
        .context("read elevated browser artifacts collector exit code")?;
    let _ = unsafe { CloseHandle(execute.hProcess) };
    if exit_code != 0 {
        bail!("elevated browser artifacts collector exited with status {exit_code}");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn relaunch_elevated(_request: &BrowserArtifactsCollectRequest) -> Result<()> {
    bail!("browser artifacts elevation relaunch is only available on Windows")
}

fn build_relaunch_parameters(request: &BrowserArtifactsCollectRequest) -> String {
    let mut values = vec![
        "collect-browser-artifacts".to_string(),
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

    use super::{default_collection_log_path, default_manifest_path, plan_browser_artifact_files};

    #[test]
    fn default_browser_artifacts_metadata_paths_live_under_central_collector_root() -> Result<()> {
        let root = PathBuf::from(r"C:\evidence");
        assert_eq!(
            default_manifest_path(&root, "c:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_browser_artifacts")
                .join("manifest.json")
        );
        assert_eq!(
            default_collection_log_path(&root, r"\\?\C:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_browser_artifacts")
                .join("collection.log")
        );
        Ok(())
    }

    #[test]
    fn plan_browser_artifact_files_collects_targeted_browser_dpapi_and_supporting_hives()
    -> Result<()> {
        let temp = tempdir()?;
        let source_root = temp.path().join("shadow");
        let user_root = source_root.join("Users").join("alice");
        let chrome_default = user_root
            .join("AppData")
            .join("Local")
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default");
        let chrome_extension_version = chrome_default
            .join("Extensions")
            .join("abcdefghijklmnopabcdefghijklmnop")
            .join("1.0.0");
        let firefox_profile = user_root
            .join("AppData")
            .join("Roaming")
            .join("Mozilla")
            .join("Firefox")
            .join("Profiles")
            .join("abc.default-release");
        let dpapi = user_root
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Protect")
            .join("S-1-5-21");
        let config = source_root.join("Windows").join("System32").join("config");
        let system_protect = source_root
            .join("Windows")
            .join("System32")
            .join("Microsoft")
            .join("Protect");
        fs::create_dir_all(&chrome_default)?;
        fs::create_dir_all(&chrome_extension_version)?;
        fs::create_dir_all(&firefox_profile)?;
        fs::create_dir_all(&dpapi)?;
        fs::create_dir_all(&config)?;
        fs::create_dir_all(&system_protect)?;
        fs::write(chrome_default.join("History"), b"history")?;
        fs::write(chrome_default.join("History-wal"), b"history wal")?;
        fs::write(chrome_default.join("History.svg"), b"not a sidecar")?;
        fs::write(chrome_extension_version.join("manifest.json"), b"manifest")?;
        fs::write(chrome_extension_version.join("icon.svg"), b"extension icon")?;
        fs::write(firefox_profile.join("places.sqlite"), b"places")?;
        fs::write(dpapi.join("masterkey"), b"dpapi")?;
        fs::write(user_root.join("NTUSER.DAT"), b"ntuser")?;
        fs::write(user_root.join("ntuser.dat.LOG1"), b"ntuser log")?;
        fs::write(config.join("SOFTWARE"), b"software")?;
        fs::write(config.join("SYSTEM"), b"system")?;
        fs::write(config.join("SECURITY"), b"security")?;
        fs::write(system_protect.join("system-masterkey"), b"system dpapi")?;

        let plan = plan_browser_artifact_files("c:", &source_root)?;
        let planned = plan.files;

        assert!(planned.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Users")
                    .join("alice")
                    .join("AppData")
                    .join("Local")
                    .join("Google")
                    .join("Chrome")
                    .join("User Data")
                    .join("Default")
                    .join("History")
        }));
        assert!(planned.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Users")
                    .join("alice")
                    .join("AppData")
                    .join("Local")
                    .join("Google")
                    .join("Chrome")
                    .join("User Data")
                    .join("Default")
                    .join("Extensions")
                    .join("abcdefghijklmnopabcdefghijklmnop")
                    .join("1.0.0")
                    .join("manifest.json")
        }));
        assert!(!planned.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Users")
                    .join("alice")
                    .join("AppData")
                    .join("Local")
                    .join("Google")
                    .join("Chrome")
                    .join("User Data")
                    .join("Default")
                    .join("Extensions")
                    .join("abcdefghijklmnopabcdefghijklmnop")
                    .join("1.0.0")
                    .join("icon.svg")
        }));
        assert!(!planned.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Users")
                    .join("alice")
                    .join("AppData")
                    .join("Local")
                    .join("Google")
                    .join("Chrome")
                    .join("User Data")
                    .join("Default")
                    .join("History.svg")
        }));
        assert!(planned.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Users")
                    .join("alice")
                    .join("AppData")
                    .join("Roaming")
                    .join("Mozilla")
                    .join("Firefox")
                    .join("Profiles")
                    .join("abc.default-release")
                    .join("places.sqlite")
        }));
        assert!(planned.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Users")
                    .join("alice")
                    .join("AppData")
                    .join("Roaming")
                    .join("Microsoft")
                    .join("Protect")
                    .join("S-1-5-21")
                    .join("masterkey")
        }));
        assert!(planned.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Users")
                    .join("alice")
                    .join("NTUSER.DAT")
        }));
        assert!(planned.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Windows")
                    .join("System32")
                    .join("config")
                    .join("SECURITY")
        }));
        assert!(planned.iter().any(|file| {
            file.archive_path
                == PathBuf::from("C")
                    .join("Windows")
                    .join("System32")
                    .join("config")
                    .join("SOFTWARE")
        }));
        assert!(planned.iter().any(|file| {
            file.live_path
                == r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\History"
        }));
        Ok(())
    }
}
