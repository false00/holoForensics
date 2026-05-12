#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::collection_metadata;
use crate::collections::windows::{usn_journal, vss};
use crate::runtime_support;

const REGISTRY_COLLECTION_SCHEMA: &str = "windows_registry_collection_v1";

#[derive(Debug, Clone, Args)]
pub struct RegistryCollectCli {
    #[arg(long, help = "NTFS volume, for example C:")]
    pub volume: String,

    #[arg(
        long = "out-dir",
        help = "Output root directory for collected registry artifacts"
    )]
    pub out_dir: PathBuf,

    #[arg(
        long,
        help = "Optional collection manifest path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_registry/manifest.json"
    )]
    pub manifest: Option<PathBuf>,

    #[arg(
        long = "collection-log",
        help = "Optional collection log path; defaults to <out-dir>/$metadata/collectors/<volume>/windows_registry/collection.log"
    )]
    pub collection_log: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = RegistryCollectMethod::VssSnapshot)]
    pub method: RegistryCollectMethod,

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RegistryCollectMethod {
    RegSave,
    VssSnapshot,
}

#[derive(Debug, Clone)]
pub struct RegistryCollectRequest {
    pub volume: String,
    pub out_dir: PathBuf,
    pub manifest: Option<PathBuf>,
    pub collection_log: Option<PathBuf>,
    pub method: RegistryCollectMethod,
    pub diagnostic_log: Option<PathBuf>,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct RegistryCollectSummary {
    pub volume: String,
    pub output_root: PathBuf,
    pub manifest_path: PathBuf,
    pub collection_log_path: PathBuf,
    pub staged_paths: Vec<PathBuf>,
    pub file_records: Vec<RegistryCollectedFile>,
}

#[derive(Debug, Clone)]
pub struct RegistryProgress {
    pub progress_value: f32,
    pub detail: String,
    pub progress_text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CollectionStatus {
    Succeeded,
}

#[derive(Debug, Clone, Serialize)]
struct CollectorMetadata {
    name: String,
    version: String,
    language: String,
}

#[derive(Debug, Clone, Serialize)]
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
pub struct RegistryCollectedFile {
    pub archive_path: String,
    source_path: String,
    file_kind: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct RegistryCollectionManifest {
    metadata_schema: String,
    artifact_type: String,
    artifact_name: String,
    volume: String,
    collection_status: CollectionStatus,
    collection_time_utc: String,
    elevation: bool,
    collector: CollectorMetadata,
    method: RegistryCollectMethod,
    transaction_safe: bool,
    source_root: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    privileges_enabled: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shadow_copy: Option<ShadowCopyMetadata>,
    files: Vec<RegistryCollectedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct PlannedRegistryFile {
    source_path: PathBuf,
    archive_path: PathBuf,
    file_kind: &'static str,
}

#[derive(Debug, Clone)]
struct CopiedRegistryBundle {
    staged_paths: Vec<PathBuf>,
    file_records: Vec<RegistryCollectedFile>,
}

pub fn run(args: &RegistryCollectCli) -> Result<()> {
    let summary = collect(&RegistryCollectRequest {
        volume: args.volume.clone(),
        out_dir: args.out_dir.clone(),
        manifest: args.manifest.clone(),
        collection_log: args.collection_log.clone(),
        method: args.method,
        diagnostic_log: args.diagnostic_log.clone(),
        elevate: args.elevate,
    })?;

    println!(
        "Collected {} registry artifacts from {} into {}",
        summary.file_records.len(),
        summary.volume,
        summary.output_root.display()
    );
    println!("Manifest: {}", summary.manifest_path.display());
    println!("Collection log: {}", summary.collection_log_path.display());
    Ok(())
}

pub fn collect(request: &RegistryCollectRequest) -> Result<RegistryCollectSummary> {
    validate_request(request)?;
    let mut reporter = |_| {};
    platform::collect_with_progress(request, None, &mut reporter)
}

pub fn collect_with_progress(
    request: &RegistryCollectRequest,
    reporter: &mut dyn FnMut(RegistryProgress),
) -> Result<RegistryCollectSummary> {
    validate_request(request)?;
    platform::collect_with_progress(request, None, reporter)
}

pub fn collect_with_progress_using_shadow_copy(
    request: &RegistryCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    reporter: &mut dyn FnMut(RegistryProgress),
) -> Result<RegistryCollectSummary> {
    validate_request(request)?;
    platform::collect_with_progress(request, Some(shadow_copy), reporter)
}

pub fn default_manifest_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_manifest_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_REGISTRY_COLLECTOR,
    )
}

pub fn default_collection_log_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_log_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_REGISTRY_COLLECTOR,
    )
}

pub fn default_diagnostic_log_path(_output_root: &Path) -> PathBuf {
    runtime_support::technical_log_path()
}

fn validate_request(request: &RegistryCollectRequest) -> Result<()> {
    let _ = usn_journal::normalize_volume(&request.volume)?;
    if request.out_dir.as_os_str().is_empty() {
        bail!("--out-dir must not be empty");
    }
    Ok(())
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn volume_archive_root(volume: &str) -> Result<PathBuf> {
    let normalized = usn_journal::normalize_volume(volume)?;
    Ok(PathBuf::from(normalized.trim_end_matches(':')))
}

fn path_from_segments(segments: &[&str]) -> PathBuf {
    let mut path = PathBuf::new();
    for segment in segments {
        path.push(segment);
    }
    path
}

fn should_collect_user_profile(profile_name: &str) -> bool {
    let normalized = profile_name.trim().to_ascii_lowercase();
    !matches!(
        normalized.as_str(),
        "all users" | "default" | "default user" | "defaultuser0" | "public"
    )
}

fn normalize_archive_path_string(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn plan_registry_copy_paths(volume: &str, source_root: &Path) -> Result<Vec<PlannedRegistryFile>> {
    let archive_root = volume_archive_root(volume)?;
    let mut planned = BTreeMap::<String, PlannedRegistryFile>::new();

    for relative_path in [
        path_from_segments(&["Windows", "System32", "config", "SYSTEM"]),
        path_from_segments(&["Windows", "System32", "config", "SOFTWARE"]),
        path_from_segments(&["Windows", "System32", "config", "SAM"]),
        path_from_segments(&["Windows", "System32", "config", "SECURITY"]),
        path_from_segments(&["Windows", "System32", "config", "DEFAULT"]),
        path_from_segments(&["Windows", "System32", "config", "COMPONENTS"]),
        path_from_segments(&["Windows", "AppCompat", "Programs", "Amcache.hve"]),
    ] {
        add_hive_with_sidecars(
            &mut planned,
            source_root,
            &archive_root,
            &relative_path,
            "registry_hive",
        )?;
    }

    for relative_path in [
        path_from_segments(&["Boot", "BCD"]),
        path_from_segments(&["EFI", "Microsoft", "Boot", "BCD"]),
    ] {
        add_if_exists(
            &mut planned,
            source_root,
            &archive_root,
            &relative_path,
            "registry_artifact",
        )?;
    }

    for relative_path in [
        path_from_segments(&["Windows", "ServiceProfiles", "LocalService", "NTUSER.DAT"]),
        path_from_segments(&[
            "Windows",
            "ServiceProfiles",
            "LocalService",
            "AppData",
            "Local",
            "Microsoft",
            "Windows",
            "USRCLASS.DAT",
        ]),
        path_from_segments(&["Windows", "ServiceProfiles", "NetworkService", "NTUSER.DAT"]),
        path_from_segments(&[
            "Windows",
            "ServiceProfiles",
            "NetworkService",
            "AppData",
            "Local",
            "Microsoft",
            "Windows",
            "USRCLASS.DAT",
        ]),
        path_from_segments(&[
            "Windows",
            "System32",
            "config",
            "systemprofile",
            "NTUSER.DAT",
        ]),
        path_from_segments(&[
            "Windows",
            "System32",
            "config",
            "systemprofile",
            "AppData",
            "Local",
            "Microsoft",
            "Windows",
            "USRCLASS.DAT",
        ]),
    ] {
        add_hive_with_sidecars(
            &mut planned,
            source_root,
            &archive_root,
            &relative_path,
            "registry_hive",
        )?;
    }

    // Avoid traversing the legacy "Documents and Settings" compatibility junction.
    // It duplicates modern profiles under "Users" and is unstable to open from VSS device paths.
    for users_root in ["Users"] {
        let root_path = source_root.join(users_root);
        if !root_path.is_dir() {
            continue;
        }

        for entry in fs::read_dir(&root_path)
            .with_context(|| format!("read profile directory {}", root_path.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let profile_name = entry.file_name();
            let profile_name_text = profile_name.to_string_lossy();
            if !should_collect_user_profile(&profile_name_text) {
                continue;
            }
            let profile_root = PathBuf::from(users_root).join(profile_name);
            add_hive_with_sidecars(
                &mut planned,
                source_root,
                &archive_root,
                &profile_root.join("NTUSER.DAT"),
                "registry_hive",
            )?;
            add_hive_with_sidecars(
                &mut planned,
                source_root,
                &archive_root,
                &profile_root
                    .join("AppData")
                    .join("Local")
                    .join("Microsoft")
                    .join("Windows")
                    .join("USRCLASS.DAT"),
                "registry_hive",
            )?;
        }
    }

    let mut values = planned.into_values().collect::<Vec<_>>();
    values.sort_by_key(|value| {
        normalize_archive_path_string(&value.archive_path).to_ascii_lowercase()
    });
    Ok(values)
}

fn add_hive_with_sidecars(
    planned: &mut BTreeMap<String, PlannedRegistryFile>,
    source_root: &Path,
    archive_root: &Path,
    relative_path: &Path,
    file_kind: &'static str,
) -> Result<()> {
    let source_path = source_root.join(relative_path);
    if !source_path.is_file() {
        return Ok(());
    }

    add_if_exists(planned, source_root, archive_root, relative_path, file_kind)?;
    for sidecar_path in discover_sidecar_paths(&source_path)? {
        if !sidecar_path.is_file() {
            continue;
        }
        let relative_sidecar = sidecar_path.strip_prefix(source_root).with_context(|| {
            format!(
                "resolve registry sidecar {} relative to {}",
                sidecar_path.display(),
                source_root.display()
            )
        })?;
        add_source_path(
            planned,
            archive_root.join(relative_sidecar),
            sidecar_path,
            "transaction_log",
        );
    }
    Ok(())
}

fn add_if_exists(
    planned: &mut BTreeMap<String, PlannedRegistryFile>,
    source_root: &Path,
    archive_root: &Path,
    relative_path: &Path,
    file_kind: &'static str,
) -> Result<()> {
    let source_path = source_root.join(relative_path);
    if source_path.is_file() {
        add_source_path(
            planned,
            archive_root.join(relative_path),
            source_path,
            file_kind,
        );
    }
    Ok(())
}

fn add_source_path(
    planned: &mut BTreeMap<String, PlannedRegistryFile>,
    archive_path: PathBuf,
    source_path: PathBuf,
    file_kind: &'static str,
) {
    let key = source_path.display().to_string().to_ascii_lowercase();
    planned.entry(key).or_insert(PlannedRegistryFile {
        source_path,
        archive_path,
        file_kind,
    });
}

fn discover_sidecar_paths(hive_path: &Path) -> Result<Vec<PathBuf>> {
    let Some(parent) = hive_path.parent() else {
        return Ok(Vec::new());
    };
    let Some(file_name) = hive_path.file_name().and_then(|value| value.to_str()) else {
        return Ok(Vec::new());
    };

    let base_name = file_name.to_ascii_lowercase();
    let mut sidecars = fs::read_dir(parent)
        .with_context(|| format!("read registry sidecar directory {}", parent.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|candidate| {
            candidate
                .file_name()
                .and_then(|value| value.to_str())
                .map(|value| {
                    let value = value.to_ascii_lowercase();
                    value == format!("{base_name}.log")
                        || value == format!("{base_name}.log1")
                        || value == format!("{base_name}.log2")
                        || value.ends_with(".blf")
                        || value.ends_with(".regtrans-ms")
                })
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    sidecars.sort_by_key(|path| path.display().to_string().to_ascii_lowercase());
    Ok(sidecars)
}

fn copy_registry_from_source_root(
    volume: &str,
    source_root: &Path,
    output_root: &Path,
) -> Result<CopiedRegistryBundle> {
    let planned = plan_registry_copy_paths(volume, source_root)?;
    copy_planned_registry_files(planned, output_root)
}

fn copy_registry_from_source_root_with_progress(
    volume: &str,
    source_root: &Path,
    output_root: &Path,
    reporter: &mut dyn FnMut(RegistryProgress),
) -> Result<CopiedRegistryBundle> {
    let planned = plan_registry_copy_paths(volume, source_root)?;
    let total = planned.len();
    if total == 0 {
        reporter(RegistryProgress {
            progress_value: 0.9,
            detail: "No registry artifacts were present in the VSS snapshot.".to_string(),
            progress_text: "0 artifacts".to_string(),
        });
    } else {
        reporter(RegistryProgress {
            progress_value: 0.18,
            detail: "Copying registry artifacts from the VSS snapshot.".to_string(),
            progress_text: format!("0 / {total} artifacts"),
        });
    }
    copy_planned_registry_files_with_progress(planned, output_root, 0.18, 0.76, reporter)
}

fn copy_planned_registry_files(
    planned: Vec<PlannedRegistryFile>,
    output_root: &Path,
) -> Result<CopiedRegistryBundle> {
    let mut staged_paths = Vec::new();
    let mut file_records = Vec::new();

    for planned_file in planned {
        let destination_path = output_root.join(&planned_file.archive_path);
        let (size, sha256) = copy_file_with_sha256(&planned_file.source_path, &destination_path)?;
        staged_paths.push(destination_path.clone());
        file_records.push(RegistryCollectedFile {
            archive_path: normalize_archive_path_string(&planned_file.archive_path),
            source_path: planned_file.source_path.display().to_string(),
            file_kind: planned_file.file_kind.to_string(),
            size,
            sha256,
        });
    }

    Ok(CopiedRegistryBundle {
        staged_paths,
        file_records,
    })
}

fn copy_planned_registry_files_with_progress(
    planned: Vec<PlannedRegistryFile>,
    output_root: &Path,
    progress_base: f32,
    progress_span: f32,
    reporter: &mut dyn FnMut(RegistryProgress),
) -> Result<CopiedRegistryBundle> {
    let total = planned.len();
    let mut staged_paths = Vec::new();
    let mut file_records = Vec::new();

    for (index, planned_file) in planned.into_iter().enumerate() {
        let destination_path = output_root.join(&planned_file.archive_path);
        let archive_name = normalize_archive_path_string(&planned_file.archive_path);
        reporter(RegistryProgress {
            progress_value: if total == 0 {
                progress_base
            } else {
                progress_base + (progress_span * (index as f32 / total as f32))
            },
            detail: format!("Copying {archive_name}"),
            progress_text: format!("{index} / {total} artifacts"),
        });
        let (size, sha256) = copy_file_with_sha256(&planned_file.source_path, &destination_path)?;
        staged_paths.push(destination_path.clone());
        file_records.push(RegistryCollectedFile {
            archive_path: archive_name.clone(),
            source_path: planned_file.source_path.display().to_string(),
            file_kind: planned_file.file_kind.to_string(),
            size,
            sha256,
        });
        reporter(RegistryProgress {
            progress_value: if total == 0 {
                progress_base + progress_span
            } else {
                progress_base + (progress_span * ((index + 1) as f32 / total as f32))
            },
            detail: format!("Copied {archive_name}"),
            progress_text: format!("{} / {} artifacts", index + 1, total),
        });
    }

    Ok(CopiedRegistryBundle {
        staged_paths,
        file_records,
    })
}

fn copy_file_with_sha256(source_path: &Path, destination_path: &Path) -> Result<(u64, String)> {
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create directory {}", parent.display()))?;
    }

    copy_registry_source_file(source_path, destination_path)?;
    let size = fs::metadata(destination_path)
        .with_context(|| format!("metadata {}", destination_path.display()))?
        .len();
    let sha256 = sha256_file(destination_path)?;
    Ok((size, sha256))
}

#[cfg(target_os = "windows")]
fn copy_registry_source_file(source_path: &Path, destination_path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows::Win32::Storage::FileSystem::CopyFileW;
    use windows::core::PCWSTR;

    let source_wide = source_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();
    let destination_wide = destination_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    unsafe {
        CopyFileW(
            PCWSTR(source_wide.as_ptr()),
            PCWSTR(destination_wide.as_ptr()),
            false,
        )
    }
    .with_context(|| {
        format!(
            "copy {} -> {}",
            source_path.display(),
            destination_path.display()
        )
    })
}

#[cfg(not(target_os = "windows"))]
fn copy_registry_source_file(source_path: &Path, destination_path: &Path) -> Result<()> {
    fs::copy(source_path, destination_path)
        .map(|_| ())
        .with_context(|| {
            format!(
                "copy {} -> {}",
                source_path.display(),
                destination_path.display()
            )
        })
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

fn write_manifest(path: &Path, manifest: &RegistryCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create manifest directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(manifest)?;
    fs::write(path, bytes).with_context(|| format!("write manifest {}", path.display()))
}

fn write_collection_log(
    path: &Path,
    volume: &str,
    source_root: &str,
    method: RegistryCollectMethod,
    files: &[RegistryCollectedFile],
    warnings: &[String],
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create collection log directory {}", parent.display()))?;
    }
    let file = File::create(path).with_context(|| format!("create log {}", path.display()))?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "registry collection volume={volume}")?;
    writeln!(writer, "source_root={source_root}")?;
    writeln!(
        writer,
        "method={}",
        match method {
            RegistryCollectMethod::RegSave => "reg_save",
            RegistryCollectMethod::VssSnapshot => "vss_snapshot",
        }
    )?;
    for entry in files {
        writeln!(
            writer,
            "copied {} kind={} size={} sha256={}",
            entry.archive_path, entry.file_kind, entry.size, entry.sha256
        )?;
    }
    if !warnings.is_empty() {
        writeln!(writer, "warnings={}", warnings.len())?;
        for warning in warnings {
            writeln!(writer, "warning {warning}")?;
        }
    }
    writeln!(writer, "files={}", files.len())?;
    writer
        .flush()
        .with_context(|| format!("flush log {}", path.display()))
}

#[cfg(target_os = "windows")]
mod platform {
    use std::ffi::c_void;
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result, anyhow, bail};
    use chrono::{SecondsFormat, Utc};
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND, GetLastError,
        HANDLE, LUID, WIN32_ERROR,
    };
    use windows::Win32::Security::{
        AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES,
        TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::Storage::FileSystem::GetVolumeInformationW;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, REG_EXPAND_SZ, REG_LATEST_FORMAT, REG_SZ,
        RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RegCloseKey, RegEnumKeyExW, RegGetValueW,
        RegOpenKeyExW, RegSaveKeyExW,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
    };
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWDEFAULT;
    use windows::core::{PCWSTR, PWSTR, w};

    use super::{
        CollectionStatus, CollectorMetadata, CopiedRegistryBundle, REGISTRY_COLLECTION_SCHEMA,
        RegistryCollectMethod, RegistryCollectRequest, RegistryCollectSummary,
        RegistryCollectedFile, RegistryCollectionManifest, RegistryProgress, ShadowCopyMetadata,
        copy_registry_from_source_root_with_progress, default_collection_log_path,
        default_diagnostic_log_path, default_manifest_path, normalize_archive_path_string,
        path_from_segments, sha256_file, usn_journal, vss, write_collection_log, write_manifest,
    };

    struct DiagnosticLog {
        file: File,
        path: PathBuf,
    }

    #[derive(Default)]
    struct CollectionState {
        warnings: Vec<String>,
        privileges_enabled: Vec<String>,
        shadow_copy: Option<ShadowCopyMetadata>,
    }

    struct TokenHandle(HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    struct RegistryKey(HKEY);

    impl Drop for RegistryKey {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    struct ProcessHandle(HANDLE);

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    #[derive(Debug, Clone)]
    struct RegSavePlan {
        root: HKEY,
        subkey: String,
        source_path: String,
        archive_path: PathBuf,
        optional: bool,
    }

    #[derive(Debug, serde::Deserialize)]
    struct PersistedRegistryManifest {
        #[serde(default)]
        files: Vec<RegistryCollectedFile>,
    }

    impl DiagnosticLog {
        fn open(path: &Path) -> Result<Self> {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create diagnostic directory {}", parent.display()))?;
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("open diagnostic log {}", path.display()))?;
            Ok(Self {
                file,
                path: path.to_path_buf(),
            })
        }

        fn log<S>(&mut self, line: S) -> Result<()>
        where
            S: AsRef<str>,
        {
            writeln!(self.file, "{}", line.as_ref())
                .with_context(|| format!("write diagnostic log {}", self.path.display()))?;
            self.file
                .flush()
                .with_context(|| format!("flush diagnostic log {}", self.path.display()))
        }
    }

    pub fn collect_with_progress(
        request: &RegistryCollectRequest,
        shared_shadow_copy: Option<&vss::ShadowCopy>,
        reporter: &mut dyn FnMut(RegistryProgress),
    ) -> Result<RegistryCollectSummary> {
        let volume = usn_journal::normalize_volume(&request.volume)?;
        fs::create_dir_all(&request.out_dir)
            .with_context(|| format!("create output root {}", request.out_dir.display()))?;
        let manifest_path = request
            .manifest
            .clone()
            .unwrap_or(default_manifest_path(&request.out_dir, &volume)?);
        let collection_log_path = request
            .collection_log
            .clone()
            .unwrap_or(default_collection_log_path(&request.out_dir, &volume)?);
        let diagnostic_path = request
            .diagnostic_log
            .clone()
            .unwrap_or_else(|| default_diagnostic_log_path(&request.out_dir));

        let mut diagnostic = DiagnosticLog::open(&diagnostic_path)?;
        reporter(RegistryProgress {
            progress_value: 0.02,
            detail: format!("Preparing registry collection on {volume}."),
            progress_text: "Starting".to_string(),
        });
        diagnostic.log(format!("normalized volume={volume}"))?;
        diagnostic.log(format!("output root={}", request.out_dir.display()))?;
        diagnostic.log(format!("manifest path={}", manifest_path.display()))?;
        diagnostic.log(format!(
            "collection log path={}",
            collection_log_path.display()
        ))?;

        let elevated = is_process_elevated()?;
        diagnostic.log(format!("process elevated={elevated}"))?;
        if !elevated && request.elevate {
            reporter(RegistryProgress {
                progress_value: 0.04,
                detail: "Waiting for elevation approval.".to_string(),
                progress_text: "UAC".to_string(),
            });
            diagnostic.log("requesting UAC relaunch")?;
            relaunch_elevated(request, &mut diagnostic)?;
            println!("Technical log: {}", diagnostic_path.display());
            return load_existing_summary(
                &volume,
                &request.out_dir,
                &manifest_path,
                &collection_log_path,
            );
        }

        let volume_root = volume_root_path(&volume)?;
        diagnostic.log(format!("volume root={volume_root}"))?;
        let file_system_name = query_volume_file_system(&volume)?;
        diagnostic.log(format!("volume file_system={file_system_name}"))?;
        if !file_system_name.eq_ignore_ascii_case("NTFS") {
            bail!(
                "registry collection requires an NTFS volume; {} is {}",
                volume,
                file_system_name
            );
        }

        let mut state = CollectionState::default();
        for privilege in ["SeBackupPrivilege", "SeRestorePrivilege"] {
            match enable_privilege(privilege) {
                Ok(()) => {
                    state.privileges_enabled.push(privilege.to_string());
                    diagnostic.log(format!("enabled privilege {privilege}"))?;
                }
                Err(error) => {
                    let message = format!("could not enable {privilege}: {error}");
                    state.warnings.push(message.clone());
                    diagnostic.log(message)?;
                }
            }
        }
        reporter(RegistryProgress {
            progress_value: 0.08,
            detail: "Privileges enabled. Preparing registry source access.".to_string(),
            progress_text: "Privileges ready".to_string(),
        });

        let (source_root, mut staged_paths, file_records) = match request.method {
            RegistryCollectMethod::RegSave => {
                let message = "RegSave exports are logical hive saves; original transaction logs are not preserved in this mode.";
                state.warnings.push(message.to_string());
                diagnostic.log(message)?;
                let message = "Per-user registry exports are disabled in RegSave mode on this build because user-hive saves are currently unstable.";
                state.warnings.push(message.to_string());
                diagnostic.log(message)?;

                diagnostic.log("exporting registry hives via RegSaveKeyExW")?;
                let CopiedRegistryBundle {
                    staged_paths,
                    file_records,
                } = export_registry_via_regsave(
                    &volume,
                    &request.out_dir,
                    &mut diagnostic,
                    &mut state.warnings,
                    reporter,
                )?;
                (PathBuf::from(&volume_root), staged_paths, file_records)
            }
            RegistryCollectMethod::VssSnapshot => {
                let owned_shadow_copy;
                let (shadow_copy, owns_shadow_copy) = if let Some(shadow_copy) = shared_shadow_copy
                {
                    reporter(RegistryProgress {
                        progress_value: 0.12,
                        detail: format!("Using shared VSS snapshot for {volume}."),
                        progress_text: "Snapshot ready".to_string(),
                    });
                    diagnostic.log(format!(
                        "using shared registry VSS snapshot id={} device_object={}",
                        shadow_copy.id, shadow_copy.device_object
                    ))?;
                    (shadow_copy, false)
                } else {
                    reporter(RegistryProgress {
                        progress_value: 0.12,
                        detail: format!("Creating VSS snapshot for {volume}."),
                        progress_text: "Creating snapshot".to_string(),
                    });
                    diagnostic.log("creating registry VSS snapshot")?;
                    owned_shadow_copy = vss::create_shadow_copy(&volume)?;
                    diagnostic.log(format!(
                        "created shadow copy id={} device_object={}",
                        owned_shadow_copy.id, owned_shadow_copy.device_object
                    ))?;
                    (&owned_shadow_copy, true)
                };
                state.shadow_copy = Some(shadow_copy_metadata(
                    shadow_copy,
                    owns_shadow_copy,
                    false,
                    !owns_shadow_copy,
                ));

                let shadow_root = vss::shadow_copy_source_root(&shadow_copy.device_object);
                reporter(RegistryProgress {
                    progress_value: 0.16,
                    detail: "VSS snapshot ready. Enumerating registry artifacts.".to_string(),
                    progress_text: "Snapshot ready".to_string(),
                });
                diagnostic.log(format!(
                    "copying registry hives from {}",
                    shadow_root.display()
                ))?;
                let copy_result = copy_registry_from_source_root_with_progress(
                    &volume,
                    &shadow_root,
                    &request.out_dir,
                    reporter,
                );
                if owns_shadow_copy {
                    diagnostic.log(format!("deleting shadow copy {}", shadow_copy.id))?;
                    let delete_result = vss::delete_shadow_copy(&shadow_copy.id);
                    match delete_result {
                        Ok(()) => {
                            if let Some(metadata) = state.shadow_copy.as_mut() {
                                metadata.deleted = true;
                            }
                            diagnostic.log(format!("deleted shadow copy {}", shadow_copy.id))?;
                        }
                        Err(error) => {
                            let message = format!(
                                "could not delete shadow copy {}: {error:#}",
                                shadow_copy.id
                            );
                            state.warnings.push(message.clone());
                            diagnostic.log(message)?;
                        }
                    }
                } else {
                    diagnostic.log(format!(
                        "leaving shared shadow copy {} for archive workflow cleanup",
                        shadow_copy.id
                    ))?;
                }

                let CopiedRegistryBundle {
                    staged_paths,
                    file_records,
                } = copy_result?;
                (shadow_root, staged_paths, file_records)
            }
        };

        if file_records.is_empty() {
            let message = format!(
                "no registry hives were exported for {}",
                source_root.display()
            );
            state.warnings.push(message.clone());
            diagnostic.log(message)?;
        } else {
            diagnostic.log(format!("copied {} registry artifacts", file_records.len()))?;
            for file in &file_records {
                diagnostic.log(format!(
                    "copied {} kind={} size={} sha256={}",
                    file.archive_path, file.file_kind, file.size, file.sha256
                ))?;
            }
        }

        reporter(RegistryProgress {
            progress_value: 0.96,
            detail: "Writing registry manifest and collection log.".to_string(),
            progress_text: format!("{} artifacts staged", file_records.len()),
        });

        let manifest = RegistryCollectionManifest {
            metadata_schema: REGISTRY_COLLECTION_SCHEMA.to_string(),
            artifact_type: "windows_registry_hive_bundle".to_string(),
            artifact_name: "Windows Registry Hives".to_string(),
            volume: volume.clone(),
            collection_status: CollectionStatus::Succeeded,
            collection_time_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            elevation: elevated,
            collector: CollectorMetadata {
                name: "holo-forensics".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                language: "rust".to_string(),
            },
            method: request.method,
            transaction_safe: matches!(request.method, RegistryCollectMethod::VssSnapshot),
            source_root: source_root.display().to_string(),
            privileges_enabled: state.privileges_enabled.clone(),
            shadow_copy: state.shadow_copy.clone(),
            files: file_records.clone(),
            warnings: state.warnings.clone(),
        };

        write_manifest(&manifest_path, &manifest)
            .with_context(|| format!("write manifest {}", manifest_path.display()))?;
        write_collection_log(
            &collection_log_path,
            &volume,
            &source_root.display().to_string(),
            request.method,
            &file_records,
            &state.warnings,
        )
        .with_context(|| format!("write collection log {}", collection_log_path.display()))?;

        staged_paths.push(manifest_path.clone());
        staged_paths.push(collection_log_path.clone());
        reporter(RegistryProgress {
            progress_value: 1.0,
            detail: "Registry collection finished and is ready for packaging.".to_string(),
            progress_text: format!("{} staged files", staged_paths.len()),
        });

        println!("Technical log: {}", diagnostic_path.display());
        Ok(RegistryCollectSummary {
            volume,
            output_root: request.out_dir.clone(),
            manifest_path,
            collection_log_path,
            staged_paths,
            file_records,
        })
    }

    fn load_existing_summary(
        volume: &str,
        output_root: &Path,
        manifest_path: &Path,
        collection_log_path: &Path,
    ) -> Result<RegistryCollectSummary> {
        let bytes = fs::read(manifest_path)
            .with_context(|| format!("read manifest {}", manifest_path.display()))?;
        let manifest: PersistedRegistryManifest = serde_json::from_slice(&bytes)
            .with_context(|| format!("decode manifest {}", manifest_path.display()))?;

        let mut staged_paths = manifest
            .files
            .iter()
            .map(|file| output_root.join(relative_path_from_archive_path(&file.archive_path)))
            .collect::<Vec<_>>();
        staged_paths.push(manifest_path.to_path_buf());
        staged_paths.push(collection_log_path.to_path_buf());

        Ok(RegistryCollectSummary {
            volume: volume.to_string(),
            output_root: output_root.to_path_buf(),
            manifest_path: manifest_path.to_path_buf(),
            collection_log_path: collection_log_path.to_path_buf(),
            staged_paths,
            file_records: manifest.files,
        })
    }

    fn relative_path_from_archive_path(archive_path: &str) -> PathBuf {
        let mut path = PathBuf::new();
        for segment in archive_path.split('/') {
            if !segment.is_empty() {
                path.push(segment);
            }
        }
        path
    }

    fn export_registry_via_regsave(
        volume: &str,
        output_root: &Path,
        diagnostic: &mut DiagnosticLog,
        warnings: &mut Vec<String>,
        reporter: &mut dyn FnMut(RegistryProgress),
    ) -> Result<CopiedRegistryBundle> {
        let plans = build_regsave_plans(volume)?;
        diagnostic.log(format!("planned {} RegSave exports", plans.len()))?;
        if plans.is_empty() {
            reporter(RegistryProgress {
                progress_value: 0.9,
                detail: "No registry hives were available for RegSave export.".to_string(),
                progress_text: "0 hives".to_string(),
            });
        }

        let mut staged_paths = Vec::new();
        let mut file_records = Vec::new();

        let total = plans.len();
        for (index, plan) in plans.into_iter().enumerate() {
            let destination_path = output_root.join(&plan.archive_path);
            reporter(RegistryProgress {
                progress_value: 0.16 + (0.72 * (index as f32 / total.max(1) as f32)),
                detail: format!("Saving {}", plan.source_path),
                progress_text: format!("{index} / {total} hives"),
            });
            diagnostic.log(format!(
                "saving {} -> {}",
                plan.source_path,
                destination_path.display()
            ))?;
            match save_registry_key(plan.root, &plan.subkey, &destination_path, diagnostic) {
                Ok(true) => {
                    diagnostic.log(format!("read metadata for {}", destination_path.display()))?;
                    let size = fs::metadata(&destination_path)
                        .with_context(|| format!("metadata {}", destination_path.display()))?
                        .len();
                    diagnostic.log(format!("hash {} size={}", destination_path.display(), size))?;
                    let sha256 = sha256_file(&destination_path)?;
                    diagnostic.log(format!(
                        "hash complete {} sha256={}",
                        destination_path.display(),
                        sha256
                    ))?;
                    diagnostic.log(format!(
                        "saved {} size={} sha256={}",
                        destination_path.display(),
                        size,
                        sha256
                    ))?;
                    staged_paths.push(destination_path);
                    file_records.push(RegistryCollectedFile {
                        archive_path: normalize_archive_path_string(&plan.archive_path),
                        source_path: plan.source_path,
                        file_kind: "registry_hive".to_string(),
                        size,
                        sha256,
                    });
                    reporter(RegistryProgress {
                        progress_value: 0.16 + (0.72 * ((index + 1) as f32 / total.max(1) as f32)),
                        detail: format!(
                            "Saved {}",
                            file_records
                                .last()
                                .map(|file| file.archive_path.as_str())
                                .unwrap_or("registry hive")
                        ),
                        progress_text: format!("{} / {} hives", index + 1, total),
                    });
                }
                Ok(false) => {
                    let message = format!(
                        "registry key {} was not available for export",
                        plan.source_path
                    );
                    warnings.push(message.clone());
                    diagnostic.log(message)?;
                    reporter(RegistryProgress {
                        progress_value: 0.16 + (0.72 * ((index + 1) as f32 / total.max(1) as f32)),
                        detail: format!("Skipped {}", plan.source_path),
                        progress_text: format!("{} / {} hives", index + 1, total),
                    });
                }
                Err(error) => {
                    let message = format!("could not export {}: {error:#}", plan.source_path);
                    warnings.push(message.clone());
                    diagnostic.log(message)?;
                    reporter(RegistryProgress {
                        progress_value: 0.16 + (0.72 * ((index + 1) as f32 / total.max(1) as f32)),
                        detail: format!("Continuing after {}", plan.source_path),
                        progress_text: format!("{} / {} hives", index + 1, total),
                    });
                }
            }
        }

        Ok(CopiedRegistryBundle {
            staged_paths,
            file_records,
        })
    }

    fn build_regsave_plans(volume: &str) -> Result<Vec<RegSavePlan>> {
        let archive_root = PathBuf::from(volume.trim_end_matches(':'));
        let plans = vec![
            regsave_plan(
                HKEY_LOCAL_MACHINE,
                "SYSTEM",
                r"HKLM\SYSTEM",
                archive_root.join(path_from_segments(&[
                    "Windows", "System32", "config", "SYSTEM",
                ])),
                false,
            ),
            regsave_plan(
                HKEY_LOCAL_MACHINE,
                "SOFTWARE",
                r"HKLM\SOFTWARE",
                archive_root.join(path_from_segments(&[
                    "Windows", "System32", "config", "SOFTWARE",
                ])),
                false,
            ),
            regsave_plan(
                HKEY_LOCAL_MACHINE,
                "SAM",
                r"HKLM\SAM",
                archive_root.join(path_from_segments(&[
                    "Windows", "System32", "config", "SAM",
                ])),
                false,
            ),
            regsave_plan(
                HKEY_LOCAL_MACHINE,
                "SECURITY",
                r"HKLM\SECURITY",
                archive_root.join(path_from_segments(&[
                    "Windows", "System32", "config", "SECURITY",
                ])),
                false,
            ),
            regsave_plan(
                HKEY_USERS,
                ".DEFAULT",
                r"HKU\.DEFAULT",
                archive_root.join(path_from_segments(&[
                    "Windows", "System32", "config", "DEFAULT",
                ])),
                false,
            ),
            regsave_plan(
                HKEY_LOCAL_MACHINE,
                "COMPONENTS",
                r"HKLM\COMPONENTS",
                archive_root.join(path_from_segments(&[
                    "Windows",
                    "System32",
                    "config",
                    "COMPONENTS",
                ])),
                true,
            ),
        ];

        Ok(plans)
    }

    fn regsave_plan(
        root: HKEY,
        subkey: &str,
        source_path: &str,
        archive_path: PathBuf,
        optional: bool,
    ) -> RegSavePlan {
        RegSavePlan {
            root,
            subkey: subkey.to_string(),
            source_path: source_path.to_string(),
            archive_path,
            optional,
        }
    }

    fn save_registry_key(
        root: HKEY,
        subkey: &str,
        destination_path: &Path,
        diagnostic: &mut DiagnosticLog,
    ) -> Result<bool> {
        if let Some(parent) = destination_path.parent() {
            diagnostic.log(format!("ensure destination directory {}", parent.display()))?;
            fs::create_dir_all(parent)
                .with_context(|| format!("create directory {}", parent.display()))?;
        }
        if destination_path.exists() {
            diagnostic.log(format!(
                "remove pre-existing destination {}",
                destination_path.display()
            ))?;
            fs::remove_file(destination_path)
                .with_context(|| format!("remove existing {}", destination_path.display()))?;
        }

        diagnostic.log(format!("open registry key {}", subkey))?;
        let Some(key) = open_registry_key(root, subkey)? else {
            return Ok(false);
        };

        let destination_wide = encode_wide_os(destination_path.as_os_str());
        diagnostic.log(format!("call RegSaveKeyExW for {}", subkey))?;
        let status = unsafe {
            RegSaveKeyExW(
                key.0,
                PCWSTR(destination_wide.as_ptr()),
                None,
                REG_LATEST_FORMAT,
            )
        };
        diagnostic.log(format!(
            "RegSaveKeyExW returned status {} for {}",
            status.0, subkey
        ))?;
        win32_ok(status, &format!("RegSaveKeyExW {}", subkey))?;
        // RegCloseKey on handles used for live hive saves is currently unstable on this host.
        // Leak the small number of export handles for the process lifetime instead of aborting.
        std::mem::forget(key);
        Ok(true)
    }

    fn open_registry_key(root: HKEY, subkey: &str) -> Result<Option<RegistryKey>> {
        let subkey_wide = encode_wide(subkey);
        let mut raw_key = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                root,
                PCWSTR(subkey_wide.as_ptr()),
                Some(0),
                KEY_READ,
                &mut raw_key,
            )
        };
        if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
            return Ok(None);
        }
        win32_ok(status, &format!("RegOpenKeyExW {}", subkey))?;
        Ok(Some(RegistryKey(raw_key)))
    }

    fn enumerate_subkeys(key: &RegistryKey) -> Result<Vec<String>> {
        let mut values = Vec::new();
        let mut index = 0u32;

        loop {
            let mut name_buffer = vec![0u16; 256];
            let mut name_len = name_buffer.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    key.0,
                    index,
                    Some(PWSTR(name_buffer.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(PWSTR::null()),
                    None,
                    None,
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            win32_ok(status, &format!("RegEnumKeyExW index={index}"))?;
            values.push(decode_wide(&name_buffer[..name_len as usize]));
            index += 1;
        }

        Ok(values)
    }

    fn query_registry_string_value(
        root: HKEY,
        subkey: &str,
        value_name: &str,
    ) -> Result<Option<String>> {
        let subkey_wide = encode_wide(subkey);
        let value_wide = encode_wide(value_name);
        let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ;
        let mut value_type = REG_SZ;
        let mut bytes = 0u32;
        let status = unsafe {
            RegGetValueW(
                root,
                PCWSTR(subkey_wide.as_ptr()),
                PCWSTR(value_wide.as_ptr()),
                flags,
                Some(&mut value_type),
                None,
                Some(&mut bytes),
            )
        };
        if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
            return Ok(None);
        }
        win32_ok(status, &format!(r"RegGetValueW {}\{}", subkey, value_name))?;
        if !(value_type == REG_SZ || value_type == REG_EXPAND_SZ) || bytes == 0 {
            return Ok(None);
        }

        let mut buffer = vec![0u8; bytes as usize];
        let status = unsafe {
            RegGetValueW(
                root,
                PCWSTR(subkey_wide.as_ptr()),
                PCWSTR(value_wide.as_ptr()),
                flags,
                Some(&mut value_type),
                Some(buffer.as_mut_ptr().cast::<c_void>()),
                Some(&mut bytes),
            )
        };
        win32_ok(status, &format!(r"RegGetValueW {}\{}", subkey, value_name))?;
        let wide_len = (bytes as usize / 2).max(1);
        let wide = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u16>(), wide_len) };
        Ok(Some(decode_wide(wide)))
    }

    fn win32_ok(status: WIN32_ERROR, context: &str) -> Result<()> {
        if status.0 == 0 {
            Ok(())
        } else {
            Err(anyhow!("{context} failed with Win32 error {}", status.0))
        }
    }

    fn volume_root_path(volume: &str) -> Result<String> {
        Ok(format!("{}\\", usn_journal::normalize_volume(volume)?))
    }

    fn query_volume_file_system(volume: &str) -> Result<String> {
        let root_path = volume_root_path(volume)?;
        let root_path_wide = encode_wide(&root_path);
        let mut file_system_name = [0u16; 64];

        unsafe {
            GetVolumeInformationW(
                PCWSTR(root_path_wide.as_ptr()),
                None,
                None,
                None,
                None,
                Some(&mut file_system_name),
            )
        }
        .with_context(|| format!("query volume information for {}", root_path))?;

        Ok(decode_wide(&file_system_name))
    }

    fn is_process_elevated() -> Result<bool> {
        let mut raw_token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) }
            .context("open current process token for elevation check")?;
        let token = TokenHandle(raw_token);

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>()),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        }
        .context("query token elevation state")?;

        Ok(elevation.TokenIsElevated != 0)
    }

    fn relaunch_elevated(
        args: &RegistryCollectRequest,
        diagnostic: &mut DiagnosticLog,
    ) -> Result<()> {
        let current_exe = std::env::current_exe().context("resolve current executable path")?;
        let current_dir = std::env::current_dir().context("resolve current working directory")?;
        let parameters = build_relaunch_parameters(args);

        diagnostic.log(format!(
            "relaunch exe={} cwd={} params={}",
            current_exe.display(),
            current_dir.display(),
            parameters
        ))?;

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

        unsafe { ShellExecuteExW(&mut execute) }.context("launch elevated collector via UAC")?;
        if execute.hProcess.is_invalid() {
            bail!("UAC launch did not return a process handle to wait on");
        }

        let process = ProcessHandle(execute.hProcess);
        diagnostic.log("requested elevated child launch and waiting for completion")?;
        unsafe {
            WaitForSingleObject(process.0, INFINITE);
        }

        let mut exit_code = 0u32;
        unsafe { GetExitCodeProcess(process.0, &mut exit_code) }
            .context("read elevated collector exit code")?;
        diagnostic.log(format!(
            "elevated child completed with exit_code={exit_code}"
        ))?;
        if exit_code != 0 {
            bail!("elevated collector exited with status {exit_code}");
        }
        Ok(())
    }

    fn build_relaunch_parameters(args: &RegistryCollectRequest) -> String {
        let mut values = vec![
            "collect-registry".to_string(),
            "--volume".to_string(),
            args.volume.clone(),
            "--out-dir".to_string(),
            args.out_dir.display().to_string(),
            "--method".to_string(),
            match args.method {
                RegistryCollectMethod::RegSave => "reg-save".to_string(),
                RegistryCollectMethod::VssSnapshot => "vss-snapshot".to_string(),
            },
        ];

        if let Some(manifest) = args.manifest.as_ref() {
            values.push("--manifest".to_string());
            values.push(manifest.display().to_string());
        }
        if let Some(collection_log) = args.collection_log.as_ref() {
            values.push("--collection-log".to_string());
            values.push(collection_log.display().to_string());
        }
        if let Some(diagnostic_log) = args.diagnostic_log.as_ref() {
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

    fn enable_privilege(privilege_name: &str) -> Result<()> {
        let mut raw_token = HANDLE::default();
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut raw_token,
            )
        }
        .context("open current process token")?;
        let token = TokenHandle(raw_token);

        let mut luid = LUID::default();
        let privilege_name_wide = encode_wide(privilege_name);
        unsafe { LookupPrivilegeValueW(None, PCWSTR(privilege_name_wide.as_ptr()), &mut luid) }
            .with_context(|| format!("resolve {}", privilege_name))?;

        let mut privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        unsafe { AdjustTokenPrivileges(token.0, false, Some(&mut privileges), 0, None, None) }
            .with_context(|| format!("enable {}", privilege_name))?;
        let last_error = unsafe { GetLastError() };
        if last_error.0 != 0 {
            bail!(
                "AdjustTokenPrivileges for {} completed with error code {}",
                privilege_name,
                last_error.0
            );
        }
        Ok(())
    }

    fn shadow_copy_metadata(
        shadow_copy: &vss::ShadowCopy,
        created: bool,
        deleted: bool,
        shared: bool,
    ) -> ShadowCopyMetadata {
        ShadowCopyMetadata {
            created,
            deleted,
            shared,
            id: shadow_copy.id.clone(),
            device_object: shadow_copy.device_object.clone(),
            context: shadow_copy.context.clone(),
        }
    }

    fn encode_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn encode_wide_os(value: &std::ffi::OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn decode_wide(value: &[u16]) -> String {
        let end = value
            .iter()
            .position(|character| *character == 0)
            .unwrap_or(value.len());
        String::from_utf16_lossy(&value[..end])
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use anyhow::{Result, bail};

    use super::{RegistryCollectRequest, RegistryCollectSummary, RegistryProgress, vss};

    pub fn collect_with_progress(
        _request: &RegistryCollectRequest,
        _shared_shadow_copy: Option<&vss::ShadowCopy>,
        _reporter: &mut dyn FnMut(RegistryProgress),
    ) -> Result<RegistryCollectSummary> {
        bail!("Windows registry collection is only supported on Windows hosts")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use anyhow::Result;
    use serde_json::Value;
    use tempfile::tempdir;

    use super::{
        copy_registry_from_source_root, default_collection_log_path, default_manifest_path,
        plan_registry_copy_paths,
    };

    #[test]
    fn default_registry_metadata_paths_live_under_central_collector_root() -> Result<()> {
        let root = PathBuf::from(r"C:\evidence");
        assert_eq!(
            default_manifest_path(&root, "c:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_registry")
                .join("manifest.json")
        );
        assert_eq!(
            default_collection_log_path(&root, r"\\?\C:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_registry")
                .join("collection.log")
        );
        Ok(())
    }

    #[test]
    fn plan_registry_copy_paths_includes_hives_sidecars_and_artifacts() -> Result<()> {
        let temp = tempdir()?;
        let source_root = temp.path().join("shadow");

        write_file(
            &source_root
                .join("Windows")
                .join("System32")
                .join("config")
                .join("SYSTEM"),
            b"regf-system",
        )?;
        write_file(
            &source_root
                .join("Windows")
                .join("System32")
                .join("config")
                .join("SYSTEM.LOG1"),
            b"log1",
        )?;
        write_file(
            &source_root
                .join("Windows")
                .join("System32")
                .join("config")
                .join("system.tm.blf"),
            b"blf",
        )?;
        write_file(
            &source_root.join("Users").join("Alice").join("NTUSER.DAT"),
            b"regf-user",
        )?;
        write_file(
            &source_root
                .join("Users")
                .join("Alice")
                .join("AppData")
                .join("Local")
                .join("Microsoft")
                .join("Windows")
                .join("USRCLASS.DAT"),
            b"regf-usrclass",
        )?;
        write_file(
            &source_root
                .join("Windows")
                .join("ServiceProfiles")
                .join("LocalService")
                .join("NTUSER.DAT"),
            b"regf-service",
        )?;
        write_file(
            &source_root
                .join("Windows")
                .join("AppCompat")
                .join("Programs")
                .join("Amcache.hve"),
            b"regf-amcache",
        )?;
        write_file(&source_root.join("Boot").join("BCD"), b"bcd")?;

        let planned = plan_registry_copy_paths("C:", &source_root)?;
        let archive_paths = planned
            .iter()
            .map(|value| value.archive_path.display().to_string().replace('\\', "/"))
            .collect::<Vec<_>>();

        assert!(archive_paths.contains(&"C/Windows/System32/config/SYSTEM".to_string()));
        assert!(archive_paths.contains(&"C/Windows/System32/config/SYSTEM.LOG1".to_string()));
        assert!(archive_paths.contains(&"C/Windows/System32/config/system.tm.blf".to_string()));
        assert!(archive_paths.contains(&"C/Users/Alice/NTUSER.DAT".to_string()));
        assert!(
            archive_paths.contains(
                &"C/Users/Alice/AppData/Local/Microsoft/Windows/USRCLASS.DAT".to_string()
            )
        );
        assert!(
            archive_paths
                .contains(&"C/Windows/ServiceProfiles/LocalService/NTUSER.DAT".to_string())
        );
        assert!(archive_paths.contains(&"C/Windows/AppCompat/Programs/Amcache.hve".to_string()));
        assert!(archive_paths.contains(&"C/Boot/BCD".to_string()));
        Ok(())
    }

    #[test]
    fn plan_registry_copy_paths_ignores_legacy_documents_and_settings_root() -> Result<()> {
        let temp = tempdir()?;
        let source_root = temp.path().join("shadow");

        write_file(
            &source_root.join("Users").join("Alice").join("NTUSER.DAT"),
            b"users-hive",
        )?;
        write_file(
            &source_root.join("Users").join("Default").join("NTUSER.DAT"),
            b"default-hive",
        )?;
        write_file(
            &source_root
                .join("Documents and Settings")
                .join("Alice")
                .join("NTUSER.DAT"),
            b"legacy-hive",
        )?;

        let planned = plan_registry_copy_paths("C:", &source_root)?;
        let archive_paths = planned
            .iter()
            .map(|value| value.archive_path.display().to_string().replace('\\', "/"))
            .collect::<Vec<_>>();

        assert!(archive_paths.contains(&"C/Users/Alice/NTUSER.DAT".to_string()));
        assert!(!archive_paths.contains(&"C/Users/Default/NTUSER.DAT".to_string()));
        assert!(
            !archive_paths
                .iter()
                .any(|path| path.starts_with("C/Documents and Settings/")),
            "legacy Documents and Settings paths should not be collected"
        );
        Ok(())
    }

    #[test]
    fn copy_registry_from_source_root_preserves_archive_layout_and_hashes() -> Result<()> {
        let temp = tempdir()?;
        let source_root = temp.path().join("shadow");
        let output_root = temp.path().join("out");

        write_file(
            &source_root
                .join("Windows")
                .join("System32")
                .join("config")
                .join("SOFTWARE"),
            b"regf-software",
        )?;
        write_file(
            &source_root
                .join("Windows")
                .join("System32")
                .join("config")
                .join("SOFTWARE.LOG2"),
            b"log2",
        )?;

        let copied = copy_registry_from_source_root("C:", &source_root, &output_root)?;

        assert_eq!(copied.file_records.len(), 2);
        assert!(
            output_root
                .join("C")
                .join("Windows")
                .join("System32")
                .join("config")
                .join("SOFTWARE")
                .is_file()
        );
        assert!(
            output_root
                .join("C")
                .join("Windows")
                .join("System32")
                .join("config")
                .join("SOFTWARE.LOG2")
                .is_file()
        );

        let manifest_records = copied
            .file_records
            .iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<Value>, _>>()?;
        assert_eq!(
            manifest_records[0].get("archive_path"),
            Some(&Value::from("C/Windows/System32/config/SOFTWARE"))
        );
        assert_eq!(
            manifest_records[0].get("size"),
            Some(&Value::from("regf-software".len() as u64))
        );
        assert_eq!(
            manifest_records[0].get("sha256"),
            Some(&Value::from(
                "0f44d6eee26876c9aed0d50f8275ac149d0b74de8e863abfc33e0b40ffee5e20"
            ))
        );
        Ok(())
    }

    fn write_file(path: &PathBuf, contents: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
        Ok(())
    }
}
