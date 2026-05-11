#![allow(dead_code)]

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::collections::windows::vss;
use crate::runtime_support;

const USN_METADATA_SCHEMA: &str = "usn_raw_collection_v1";

#[derive(Debug, Clone, Args)]
pub struct UsnDumpCli {
    #[arg(long, help = "NTFS volume, for example C:")]
    pub volume: String,

    #[arg(long, help = "Output path for collected $UsnJrnl:$J bytes")]
    pub out: PathBuf,

    #[arg(
        long,
        help = "Optional metadata sidecar path; defaults to <out>.metadata.json"
    )]
    pub metadata: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = UsnDumpMode::VssRawNtfs)]
    pub mode: UsnDumpMode,

    #[arg(
        long,
        help = "Preserve the full logical $UsnJrnl:$J layout with sparse holes instead of collecting only the active USN window"
    )]
    pub sparse: bool,

    #[arg(long, default_value_t = 4, help = "Sequential read chunk size in MiB")]
    pub chunk_size_mib: usize,

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
pub enum UsnDumpMode {
    DirectStream,
    VssSnapshot,
    VssRawNtfs,
}

#[derive(Debug, Clone)]
pub struct UsnProgress {
    pub progress_value: f32,
    pub detail: String,
    pub progress_text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CollectionStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OutputMode {
    ActiveWindow,
    DenseLogical,
    SparseLogical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Sha256Scope {
    LogicalStream,
    AllocatedRanges,
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize)]
struct UsnDumpMetadata {
    metadata_schema: String,
    artifact_type: String,
    artifact_name: String,
    volume: String,
    source: String,
    source_access_method: String,
    collection_status: CollectionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<CollectionErrorMetadata>,
    collection_time_utc: String,
    elevation: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    privileges_enabled: Vec<String>,
    raw_output_produced: bool,
    collector: CollectorMetadata,
    mode: UsnDumpMode,
    output_mode: OutputMode,
    transaction_safe: bool,
    journal_is_circular: bool,
    logical_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_logical_size: Option<u64>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    output_logical_base: u64,
    bytes_written: u64,
    allocated_size_written: u64,
    sparse_holes_preserved: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256_scope: Option<Sha256Scope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    volume_serial_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_system_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usn_journal_data: Option<UsnJournalMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shadow_copy: Option<ShadowCopyMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    data_runs: Vec<DataRunMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CollectorMetadata {
    name: String,
    version: String,
    language: String,
}

#[derive(Debug, Clone, Serialize)]
struct UsnJournalMetadata {
    journal_id: String,
    first_usn: String,
    next_usn: String,
    lowest_valid_usn: String,
    max_usn: String,
    maximum_size: String,
    allocation_delta: String,
}

#[derive(Debug, Clone, Serialize)]
struct CollectionErrorMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<i32>,
    message: String,
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

#[derive(Debug, Clone, Serialize)]
struct DataRunMetadata {
    logical_offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    volume_offset: Option<u64>,
    length: u64,
    sparse: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveWindowRange {
    logical_offset_base: u64,
    length: u64,
}

fn parse_u64_field(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse().ok()
    }
}

fn active_window_range(
    usn_journal_data: Option<&UsnJournalMetadata>,
    source_logical_size: u64,
) -> Option<ActiveWindowRange> {
    let usn_journal_data = usn_journal_data?;
    let start = parse_u64_field(&usn_journal_data.first_usn)?;
    let end = parse_u64_field(&usn_journal_data.next_usn)?.min(source_logical_size);
    if start >= end {
        return None;
    }
    if start == 0 && end == source_logical_size {
        return None;
    }

    Some(ActiveWindowRange {
        logical_offset_base: start,
        length: end - start,
    })
}

pub fn run(args: &UsnDumpCli) -> Result<()> {
    validate_args(args)?;
    let mut reporter = |_| {};
    platform::run_with_progress(args, None, &mut reporter)
}

pub fn run_with_progress(args: &UsnDumpCli, reporter: &mut dyn FnMut(UsnProgress)) -> Result<()> {
    validate_args(args)?;
    platform::run_with_progress(args, None, reporter)
}

pub fn run_with_progress_using_shadow_copy(
    args: &UsnDumpCli,
    shadow_copy: &vss::ShadowCopy,
    reporter: &mut dyn FnMut(UsnProgress),
) -> Result<()> {
    validate_args(args)?;
    platform::run_with_progress(args, Some(shadow_copy), reporter)
}

pub fn default_metadata_path(output_path: &Path) -> PathBuf {
    let mut metadata_name = output_path
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_else(|| "usn_journal_J.bin".into());
    metadata_name.push(".metadata.json");
    output_path.with_file_name(metadata_name)
}

pub fn default_diagnostic_log_path(_output_path: &Path) -> PathBuf {
    runtime_support::technical_log_path()
}

fn mode_cli_value(mode: UsnDumpMode) -> &'static str {
    match mode {
        UsnDumpMode::DirectStream => "direct-stream",
        UsnDumpMode::VssSnapshot => "vss-snapshot",
        UsnDumpMode::VssRawNtfs => "vss-raw-ntfs",
    }
}

pub fn normalize_volume(value: &str) -> Result<String> {
    let trimmed = value.trim().trim_end_matches(['\\', '/']);
    let trimmed = trimmed.strip_prefix(r"\\.\").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix(r"\\?\").unwrap_or(trimmed);
    let trimmed = trimmed.trim_end_matches(':');

    let mut characters = trimmed.chars();
    let Some(letter) = characters.next() else {
        bail!("volume must contain a drive letter, for example C:");
    };
    if characters.next().is_some() || !letter.is_ascii_alphabetic() {
        bail!("volume must be a single drive letter, for example C:");
    }

    Ok(format!("{}:", letter.to_ascii_uppercase()))
}

fn validate_args(args: &UsnDumpCli) -> Result<()> {
    let _ = normalize_volume(&args.volume)?;
    if args.chunk_size_mib == 0 {
        bail!("--chunk-size-mib must be greater than zero");
    }
    if args.sparse && !matches!(args.mode, UsnDumpMode::VssRawNtfs) {
        bail!("--sparse is only supported with --mode vss-raw-ntfs");
    }
    Ok(())
}

fn stream_source_path(volume: &str) -> Result<String> {
    Ok(format!(
        r"\\?\{}\$Extend\$UsnJrnl:$J",
        normalize_volume(volume)?
    ))
}

fn stream_source_paths(volume: &str) -> Result<Vec<String>> {
    let normalized = normalize_volume(volume)?;
    Ok(vec![
        format!(r"\\?\{}\$Extend\$UsnJrnl:$J", normalized),
        format!(r"\\.\{}\$Extend\$UsnJrnl:$J", normalized),
    ])
}

fn shadow_copy_source_path(device_object: &str) -> Result<String> {
    let trimmed = device_object.trim().trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        bail!("shadow copy device object cannot be empty");
    }

    Ok(format!(r"{}\$Extend\$UsnJrnl:$J", trimmed))
}

fn shadow_copy_raw_device_paths(device_object: &str) -> Result<Vec<String>> {
    let trimmed = device_object.trim().trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        bail!("shadow copy device object cannot be empty");
    }

    let canonical = if trimmed.starts_with(r"\\?\") || trimmed.starts_with(r"\\.\") {
        trimmed.to_string()
    } else {
        format!(r"\\?\{}", trimmed.trim_start_matches(['\\']))
    };

    let mut paths = vec![canonical.clone()];
    if let Some(remainder) = canonical.strip_prefix(r"\\?\") {
        paths.push(format!(r"\\.\{remainder}"));
    }
    paths.dedup();
    Ok(paths)
}

fn volume_device_path(volume: &str) -> Result<String> {
    Ok(format!(r"\\.\{}", normalize_volume(volume)?))
}

fn volume_root_path(volume: &str) -> Result<String> {
    Ok(format!("{}\\", normalize_volume(volume)?))
}

fn write_metadata(path: &Path, metadata: &UsnDumpMetadata) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(metadata)?;
    std::fs::write(path, json)?;
    Ok(())
}

#[cfg(target_os = "windows")]
mod platform {
    use std::ffi::c_void;
    use std::fs::{self, File, OpenOptions};
    use std::io::{BufReader, Read, Seek, SeekFrom, Write};
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result, anyhow, bail};
    use chrono::{SecondsFormat, Utc};
    use ntfs::attribute_value::NtfsAttributeValue;
    use ntfs::indexes::NtfsFileNameIndex;
    use ntfs::{Ntfs, NtfsAttributeType, NtfsFile, NtfsReadSeek};
    use sha2::{Digest, Sha256};
    use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES,
        TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetVolumeInformationW,
    };
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::{
        FSCTL_QUERY_USN_JOURNAL, FSCTL_SET_SPARSE, USN_JOURNAL_DATA_V0,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
    };
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWDEFAULT;
    use windows::core::{PCWSTR, w};

    use super::{
        ActiveWindowRange, CollectionErrorMetadata, CollectionStatus, CollectorMetadata,
        DataRunMetadata, OutputMode, Sha256Scope, ShadowCopyMetadata, USN_METADATA_SCHEMA,
        UsnDumpCli, UsnDumpMetadata, UsnDumpMode, UsnJournalMetadata, UsnProgress,
        active_window_range, default_diagnostic_log_path, default_metadata_path, mode_cli_value,
        normalize_volume, shadow_copy_raw_device_paths, shadow_copy_source_path,
        stream_source_paths, volume_device_path, volume_root_path, vss, write_metadata,
    };

    struct DiagnosticLog {
        file: File,
        path: PathBuf,
    }

    struct VolumeInfo {
        serial_number: String,
        file_system_name: String,
    }

    #[derive(Default)]
    struct CollectionState {
        warnings: Vec<String>,
        privileges_enabled: Vec<String>,
        volume_info: Option<VolumeInfo>,
        usn_journal_data: Option<UsnJournalMetadata>,
        shadow_copy: Option<ShadowCopyMetadata>,
        source_path: Option<String>,
        source_access_method: Option<String>,
        failure_stage: Option<String>,
    }

    struct CollectedStream {
        source_path: String,
        source_access_method: String,
        logical_size: u64,
        source_logical_size: Option<u64>,
        output_logical_base: u64,
        bytes_written: u64,
        allocated_size_written: u64,
        sha256: String,
        sha256_scope: Option<Sha256Scope>,
        output_mode: OutputMode,
        sparse_holes_preserved: bool,
        transaction_safe: bool,
        shadow_copy: Option<ShadowCopyMetadata>,
        data_runs: Vec<DataRunMetadata>,
    }

    struct OutputWriteSummary {
        logical_size: u64,
        source_logical_size: Option<u64>,
        output_logical_base: u64,
        bytes_written: u64,
        allocated_size_written: u64,
        sha256: String,
        sha256_scope: Option<Sha256Scope>,
        output_mode: OutputMode,
        sparse_holes_preserved: bool,
        data_runs: Vec<DataRunMetadata>,
    }

    struct TokenHandle(HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
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

        fn log(&mut self, message: impl AsRef<str>) -> Result<()> {
            let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
            writeln!(
                self.file,
                "[{timestamp}] pid={} source=usn-journal {}",
                std::process::id(),
                message.as_ref()
            )
            .with_context(|| format!("write diagnostic log {}", self.path.display()))?;
            self.file
                .flush()
                .with_context(|| format!("flush diagnostic log {}", self.path.display()))?;
            Ok(())
        }
    }

    impl CollectionState {
        fn set_stage(&mut self, stage: &str) {
            self.failure_stage = Some(stage.to_string());
        }
    }

    fn emit_progress(
        reporter: &mut dyn FnMut(UsnProgress),
        progress_value: f32,
        detail: impl Into<String>,
        progress_text: impl Into<String>,
    ) {
        reporter(UsnProgress {
            progress_value: progress_value.clamp(0.0, 1.0),
            detail: detail.into(),
            progress_text: progress_text.into(),
        });
    }

    #[derive(Default)]
    struct CopyProgressTracker {
        last_fraction: f32,
    }

    impl CopyProgressTracker {
        fn should_emit(&mut self, fraction: f32) -> bool {
            let clamped = fraction.clamp(0.0, 1.0);
            if clamped >= 1.0 || clamped <= 0.0 || clamped - self.last_fraction >= 0.01 {
                self.last_fraction = clamped;
                true
            } else {
                false
            }
        }
    }

    fn format_bytes_progress(bytes_written: u64, total_bytes: Option<u64>) -> String {
        let written = format_bytes(bytes_written);
        match total_bytes {
            Some(total) if total > 0 => format!("{written} / {}", format_bytes(total)),
            _ => written,
        }
    }

    fn format_bytes(value: u64) -> String {
        const KIB: f64 = 1024.0;
        const MIB: f64 = 1024.0 * 1024.0;
        const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

        let value_f64 = value as f64;
        if value_f64 >= GIB {
            format!("{:.1} GiB", value_f64 / GIB)
        } else if value_f64 >= MIB {
            format!("{:.1} MiB", value_f64 / MIB)
        } else if value_f64 >= KIB {
            format!("{:.1} KiB", value_f64 / KIB)
        } else {
            format!("{value} B")
        }
    }

    fn emit_copy_progress(
        reporter: &mut dyn FnMut(UsnProgress),
        tracker: &mut CopyProgressTracker,
        progress_base: f32,
        progress_span: f32,
        detail: &str,
        bytes_written: u64,
        total_bytes: u64,
    ) {
        if total_bytes == 0 {
            return;
        }
        let fraction = (bytes_written as f32 / total_bytes as f32).clamp(0.0, 1.0);
        if tracker.should_emit(fraction) {
            emit_progress(
                reporter,
                progress_base + (progress_span * fraction),
                detail.to_string(),
                format_bytes_progress(bytes_written, Some(total_bytes)),
            );
        }
    }

    pub fn run_with_progress(
        args: &UsnDumpCli,
        shared_shadow_copy: Option<&vss::ShadowCopy>,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<()> {
        let diagnostic_path = args
            .diagnostic_log
            .clone()
            .unwrap_or_else(|| default_diagnostic_log_path(&args.out));
        let metadata_path = args
            .metadata
            .clone()
            .unwrap_or_else(|| default_metadata_path(&args.out));
        let mut diagnostic = DiagnosticLog::open(&diagnostic_path)?;
        diagnostic.log(format!(
            "collector start volume={} out={} elevate={} mode={} sparse={}",
            args.volume,
            args.out.display(),
            args.elevate,
            mode_cli_value(args.mode),
            args.sparse
        ))?;
        if let Some(shadow_copy) = shared_shadow_copy {
            diagnostic.log(format!(
                "shared shadow copy supplied id={} device_object={} context={}",
                shadow_copy.id, shadow_copy.device_object, shadow_copy.context
            ))?;
        }
        emit_progress(
            reporter,
            0.02,
            format!("Preparing USN Journal collection on {}.", args.volume),
            "Starting".to_string(),
        );

        let mut state = CollectionState::default();

        state.set_stage("query_elevation");
        let elevated = match is_process_elevated() {
            Ok(value) => value,
            Err(error) => {
                write_failure_artifact(
                    args,
                    &args.volume,
                    &metadata_path,
                    false,
                    &state,
                    &error,
                    &mut diagnostic,
                );
                return Err(error);
            }
        };
        diagnostic.log(format!("process elevated={elevated}"))?;

        if args.elevate && !elevated {
            state.set_stage("uac_relaunch");
            emit_progress(
                reporter,
                0.04,
                "Waiting for elevation approval.".to_string(),
                "UAC".to_string(),
            );
            diagnostic.log("requesting UAC relaunch")?;
            if let Err(error) = relaunch_elevated(args, &mut diagnostic) {
                write_failure_artifact(
                    args,
                    &args.volume,
                    &metadata_path,
                    elevated,
                    &state,
                    &error,
                    &mut diagnostic,
                );
                return Err(error);
            }
            println!(
                "Requested UAC elevation. Approve the prompt to continue collection in the elevated process."
            );
            println!("Technical log: {}", diagnostic_path.display());
            return Ok(());
        }

        state.set_stage("normalize_volume");
        let volume = match normalize_volume(&args.volume) {
            Ok(value) => value,
            Err(error) => {
                write_failure_artifact(
                    args,
                    &args.volume,
                    &metadata_path,
                    elevated,
                    &state,
                    &error,
                    &mut diagnostic,
                );
                return Err(error);
            }
        };
        emit_progress(
            reporter,
            0.06,
            format!("Resolved USN source volume {volume}."),
            "Volume ready".to_string(),
        );
        let result = run_collection(
            args,
            &volume,
            elevated,
            &metadata_path,
            shared_shadow_copy,
            &mut state,
            &mut diagnostic,
            &diagnostic_path,
            reporter,
        );
        if let Err(error) = &result {
            write_failure_artifact(
                args,
                &volume,
                &metadata_path,
                elevated,
                &state,
                error,
                &mut diagnostic,
            );
        }
        result
    }

    fn run_collection(
        args: &UsnDumpCli,
        volume: &str,
        elevated: bool,
        metadata_path: &Path,
        shared_shadow_copy: Option<&vss::ShadowCopy>,
        state: &mut CollectionState,
        diagnostic: &mut DiagnosticLog,
        diagnostic_path: &Path,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<()> {
        let source_paths = stream_source_paths(volume)?;

        diagnostic.log(format!("normalized volume={volume}"))?;
        diagnostic.log(format!(
            "source path candidates={}",
            source_paths.join(" | ")
        ))?;
        diagnostic.log(format!("metadata path={}", metadata_path.display()))?;

        let chunk_size = chunk_size_bytes(args.chunk_size_mib)?;

        state.set_stage("enable_privileges");
        emit_progress(
            reporter,
            0.10,
            "Enabling privileges for USN access.".to_string(),
            "Privileges".to_string(),
        );
        diagnostic.log(
            "attempting privilege enable: SeBackupPrivilege, SeManageVolumePrivilege, SeRestorePrivilege",
        )?;
        for privilege in [
            "SeBackupPrivilege",
            "SeManageVolumePrivilege",
            "SeRestorePrivilege",
        ] {
            match enable_privilege(privilege) {
                Ok(()) => {
                    state.privileges_enabled.push(privilege.to_string());
                    diagnostic.log(format!("enabled privilege {privilege}"))?
                }
                Err(error) => {
                    let message = format!("could not enable {privilege}: {error}");
                    diagnostic.log(&message)?;
                    state.warnings.push(message);
                }
            }
        }

        state.set_stage("query_volume_metadata");
        emit_progress(
            reporter,
            0.14,
            format!("Reading NTFS volume metadata for {volume}."),
            "Volume metadata".to_string(),
        );
        diagnostic.log("querying volume metadata")?;
        let volume_info = match query_volume_info(volume) {
            Ok(info) => {
                diagnostic.log(format!(
                    "volume metadata file_system={} serial={}",
                    info.file_system_name, info.serial_number
                ))?;
                state.volume_info = Some(VolumeInfo {
                    serial_number: info.serial_number.clone(),
                    file_system_name: info.file_system_name.clone(),
                });
                Some(info)
            }
            Err(error) => {
                let message = format!("could not query volume metadata: {error}");
                diagnostic.log(&message)?;
                state.warnings.push(message);
                None
            }
        };

        if let Some(info) = volume_info.as_ref() {
            if !info.file_system_name.eq_ignore_ascii_case("NTFS") {
                bail!(
                    "USN journal collection requires an NTFS volume; {} is {}",
                    volume,
                    info.file_system_name
                );
            }
        }

        state.set_stage("query_live_usn_journal_metadata");
        emit_progress(
            reporter,
            0.20,
            "Reading live USN journal metadata.".to_string(),
            "Journal metadata".to_string(),
        );
        diagnostic.log("querying live USN journal metadata")?;
        let usn_journal_data = match query_usn_journal(volume) {
            Ok(metadata) => {
                diagnostic.log(format!(
                    "journal metadata first_usn={} next_usn={} max_usn={}",
                    metadata.first_usn, metadata.next_usn, metadata.max_usn
                ))?;
                state.usn_journal_data = Some(metadata.clone());
                Some(metadata)
            }
            Err(error) => {
                let message = format!("could not query live USN journal metadata: {error}");
                diagnostic.log(&message)?;
                state.warnings.push(message);
                None
            }
        };

        let collected = match args.mode {
            UsnDumpMode::DirectStream => {
                state.set_stage("direct_stream_copy");
                state.source_path = Some(source_paths.join(" | "));
                state.source_access_method = Some("direct_stream".to_string());
                diagnostic.log(format!(
                    "starting direct-stream copy chunk_size_mib={}",
                    args.chunk_size_mib
                ))?;
                let (source_path, output_summary) = copy_stream(
                    &source_paths,
                    &args.out,
                    chunk_size,
                    usn_journal_data.as_ref(),
                    diagnostic,
                    reporter,
                )?;
                diagnostic.log(format!(
                    "copy finished source_path={} logical_size={} bytes_written={} output_mode={:?}",
                    source_path,
                    output_summary.logical_size,
                    output_summary.bytes_written,
                    output_summary.output_mode
                ))?;

                CollectedStream {
                    source_path,
                    source_access_method: "direct_stream".to_string(),
                    logical_size: output_summary.logical_size,
                    source_logical_size: output_summary.source_logical_size,
                    output_logical_base: output_summary.output_logical_base,
                    bytes_written: output_summary.bytes_written,
                    allocated_size_written: output_summary.allocated_size_written,
                    sha256: output_summary.sha256,
                    sha256_scope: output_summary.sha256_scope,
                    output_mode: output_summary.output_mode,
                    sparse_holes_preserved: output_summary.sparse_holes_preserved,
                    transaction_safe: false,
                    shadow_copy: None,
                    data_runs: output_summary.data_runs,
                }
            }
            UsnDumpMode::VssSnapshot => {
                state.set_stage("vss_create");
                diagnostic.log(format!(
                    "starting VSS snapshot copy chunk_size_mib={}",
                    args.chunk_size_mib
                ))?;
                collect_vss_snapshot(
                    volume,
                    &args.out,
                    chunk_size,
                    usn_journal_data.as_ref(),
                    shared_shadow_copy,
                    state,
                    diagnostic,
                    reporter,
                )?
            }
            UsnDumpMode::VssRawNtfs => {
                state.set_stage("vss_create");
                diagnostic.log(format!(
                    "starting VSS raw-NTFS copy chunk_size_mib={}",
                    args.chunk_size_mib
                ))?;
                collect_vss_raw_ntfs(
                    volume,
                    &args.out,
                    chunk_size,
                    args.sparse,
                    shared_shadow_copy,
                    state,
                    diagnostic,
                    reporter,
                )?
            }
        };

        state.source_path = Some(collected.source_path.clone());
        state.source_access_method = Some(collected.source_access_method.clone());
        state.shadow_copy = collected.shadow_copy.clone();

        let metadata = UsnDumpMetadata {
            metadata_schema: USN_METADATA_SCHEMA.to_string(),
            artifact_type: "ntfs_usn_journal_raw_stream".to_string(),
            artifact_name: r"$Extend\$UsnJrnl:$J".to_string(),
            volume: volume.to_string(),
            source: collected.source_path,
            source_access_method: collected.source_access_method,
            collection_status: CollectionStatus::Succeeded,
            failure_stage: None,
            error: None,
            collection_time_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            elevation: elevated,
            privileges_enabled: state.privileges_enabled.clone(),
            raw_output_produced: true,
            collector: CollectorMetadata {
                name: "holo-forensics".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                language: "rust".to_string(),
            },
            mode: args.mode,
            output_mode: collected.output_mode,
            transaction_safe: collected.transaction_safe,
            journal_is_circular: true,
            logical_size: collected.logical_size,
            source_logical_size: collected.source_logical_size,
            output_logical_base: collected.output_logical_base,
            bytes_written: collected.bytes_written,
            allocated_size_written: collected.allocated_size_written,
            sparse_holes_preserved: collected.sparse_holes_preserved,
            sha256: collected.sha256,
            sha256_scope: collected.sha256_scope,
            volume_serial_number: state
                .volume_info
                .as_ref()
                .map(|value| value.serial_number.clone()),
            file_system_type: state
                .volume_info
                .as_ref()
                .map(|value| value.file_system_name.clone()),
            usn_journal_data,
            shadow_copy: collected.shadow_copy,
            data_runs: collected.data_runs,
            warnings: state.warnings.clone(),
        };

        diagnostic.log("writing metadata sidecar")?;
        emit_progress(
            reporter,
            0.97,
            "Writing USN metadata sidecar.".to_string(),
            "Metadata".to_string(),
        );
        write_metadata(&metadata_path, &metadata)
            .with_context(|| format!("write metadata {}", metadata_path.display()))?;
        diagnostic.log(format!("metadata written to {}", metadata_path.display()))?;
        emit_progress(
            reporter,
            1.0,
            "USN Journal collection finished and is ready for packaging.".to_string(),
            format_bytes_progress(metadata.bytes_written, Some(metadata.logical_size)),
        );

        if metadata.output_mode == OutputMode::SparseLogical {
            println!(
                "Collected {} logical bytes from {} to {} (allocated output bytes written: {})",
                metadata.logical_size,
                volume,
                args.out.display(),
                metadata.allocated_size_written
            );
        } else if metadata.output_mode == OutputMode::ActiveWindow {
            println!(
                "Collected active USN window {} bytes from {} to {} (source logical size: {}, base offset: {})",
                metadata.logical_size,
                volume,
                args.out.display(),
                metadata
                    .source_logical_size
                    .unwrap_or(metadata.logical_size),
                metadata.output_logical_base
            );
        } else {
            println!(
                "Collected {} bytes from {} to {}",
                metadata.bytes_written,
                volume,
                args.out.display()
            );
        }
        println!("Metadata: {}", metadata_path.display());
        println!("Technical log: {}", diagnostic_path.display());
        Ok(())
    }

    fn collect_vss_snapshot(
        volume: &str,
        output_path: &Path,
        chunk_size: usize,
        usn_journal_data: Option<&UsnJournalMetadata>,
        shared_shadow_copy: Option<&vss::ShadowCopy>,
        state: &mut CollectionState,
        diagnostic: &mut DiagnosticLog,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<CollectedStream> {
        let owned_shadow_copy;
        let (shadow_copy, owns_shadow_copy) = if let Some(shadow_copy) = shared_shadow_copy {
            emit_progress(
                reporter,
                0.24,
                format!("Using shared VSS snapshot for {volume}."),
                "Snapshot ready".to_string(),
            );
            diagnostic.log(format!(
                "using shared VSS snapshot id={} device_object={} context={}",
                shadow_copy.id, shadow_copy.device_object, shadow_copy.context
            ))?;
            (shadow_copy, false)
        } else {
            emit_progress(
                reporter,
                0.24,
                format!("Creating VSS snapshot for {volume}."),
                "Creating snapshot".to_string(),
            );
            diagnostic.log(format!(
                "creating VSS snapshot volume={} context={}",
                volume,
                vss::SHADOW_COPY_CONTEXT
            ))?;
            owned_shadow_copy = vss::create_shadow_copy(volume)?;
            diagnostic.log(format!(
                "shadow copy created id={} device_object={} context={}",
                owned_shadow_copy.id, owned_shadow_copy.device_object, owned_shadow_copy.context
            ))?;
            (&owned_shadow_copy, true)
        };
        state.shadow_copy = Some(shadow_copy_metadata(
            shadow_copy,
            owns_shadow_copy,
            false,
            !owns_shadow_copy,
        ));

        let source_path = shadow_copy_source_path(&shadow_copy.device_object)?;
        state.source_path = Some(source_path.clone());
        state.source_access_method = Some("vss_direct_stream".to_string());
        state.set_stage("vss_direct_stream_open");
        emit_progress(
            reporter,
            0.30,
            "VSS snapshot ready. Opening shadow-copy USN stream.".to_string(),
            "Snapshot ready".to_string(),
        );
        diagnostic.log(format!("trying shadow-copy path={source_path}"))?;
        let copy_result = match copy_stream_from_path(
            &source_path,
            output_path,
            chunk_size,
            usn_journal_data,
            reporter,
        ) {
            Ok(output_summary) => {
                diagnostic.log(format!(
                    "shadow-copy path succeeded path={} logical_size={} bytes_written={} output_mode={:?}",
                    source_path,
                    output_summary.logical_size,
                    output_summary.bytes_written,
                    output_summary.output_mode
                ))?;
                Ok(output_summary)
            }
            Err(error) => {
                diagnostic.log(format!(
                    "shadow-copy path failed path={} error={error:#}",
                    source_path
                ))?;
                Err(error)
            }
        };

        if owns_shadow_copy {
            diagnostic.log(format!("deleting shadow copy id={}", shadow_copy.id))?;
            if let Err(error) = vss::delete_shadow_copy(&shadow_copy.id) {
                let message = format!("could not delete shadow copy {}: {error:#}", shadow_copy.id);
                diagnostic.log(&message)?;
                state.warnings.push(message);
            } else {
                if let Some(metadata) = state.shadow_copy.as_mut() {
                    metadata.deleted = true;
                }
                diagnostic.log(format!("deleted shadow copy id={}", shadow_copy.id))?;
            }
        } else {
            diagnostic.log(format!(
                "leaving shared shadow copy {} for archive workflow cleanup",
                shadow_copy.id
            ))?;
        }

        let output_summary = copy_result?;

        Ok(CollectedStream {
            source_path,
            source_access_method: "vss_direct_stream".to_string(),
            logical_size: output_summary.logical_size,
            source_logical_size: output_summary.source_logical_size,
            output_logical_base: output_summary.output_logical_base,
            bytes_written: output_summary.bytes_written,
            allocated_size_written: output_summary.allocated_size_written,
            sha256: output_summary.sha256,
            sha256_scope: output_summary.sha256_scope,
            output_mode: output_summary.output_mode,
            sparse_holes_preserved: output_summary.sparse_holes_preserved,
            transaction_safe: true,
            shadow_copy: Some(shadow_copy_metadata(
                shadow_copy,
                owns_shadow_copy,
                owns_shadow_copy,
                !owns_shadow_copy,
            )),
            data_runs: output_summary.data_runs,
        })
    }

    fn collect_vss_raw_ntfs(
        volume: &str,
        output_path: &Path,
        chunk_size: usize,
        sparse_output: bool,
        shared_shadow_copy: Option<&vss::ShadowCopy>,
        state: &mut CollectionState,
        diagnostic: &mut DiagnosticLog,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<CollectedStream> {
        let owned_shadow_copy;
        let (shadow_copy, owns_shadow_copy) = if let Some(shadow_copy) = shared_shadow_copy {
            emit_progress(
                reporter,
                0.24,
                format!("Using shared VSS snapshot for {volume}."),
                "Snapshot ready".to_string(),
            );
            diagnostic.log(format!(
                "using shared VSS snapshot for raw NTFS extraction id={} device_object={} context={}",
                shadow_copy.id, shadow_copy.device_object, shadow_copy.context
            ))?;
            (shadow_copy, false)
        } else {
            emit_progress(
                reporter,
                0.24,
                format!("Creating VSS snapshot for {volume}."),
                "Creating snapshot".to_string(),
            );
            diagnostic.log(format!(
                "creating VSS snapshot for raw NTFS extraction volume={} context={}",
                volume,
                vss::SHADOW_COPY_CONTEXT
            ))?;
            owned_shadow_copy = vss::create_shadow_copy(volume)?;
            diagnostic.log(format!(
                "shadow copy created id={} device_object={} context={}",
                owned_shadow_copy.id, owned_shadow_copy.device_object, owned_shadow_copy.context
            ))?;
            (&owned_shadow_copy, true)
        };
        state.shadow_copy = Some(shadow_copy_metadata(
            shadow_copy,
            owns_shadow_copy,
            false,
            !owns_shadow_copy,
        ));

        let raw_device_paths = shadow_copy_raw_device_paths(&shadow_copy.device_object)?;
        emit_progress(
            reporter,
            0.30,
            "VSS snapshot ready. Resolving raw NTFS device path.".to_string(),
            "Snapshot ready".to_string(),
        );
        diagnostic.log(format!(
            "shadow copy raw device candidates={}",
            raw_device_paths.join(" | ")
        ))?;

        let copy_result = copy_stream_from_raw_ntfs_device_paths(
            &raw_device_paths,
            output_path,
            chunk_size,
            sparse_output,
            state,
            diagnostic,
            reporter,
        );

        if owns_shadow_copy {
            diagnostic.log(format!("deleting shadow copy id={}", shadow_copy.id))?;
            if let Err(error) = vss::delete_shadow_copy(&shadow_copy.id) {
                let message = format!("could not delete shadow copy {}: {error:#}", shadow_copy.id);
                diagnostic.log(&message)?;
                state.warnings.push(message);
            } else {
                if let Some(metadata) = state.shadow_copy.as_mut() {
                    metadata.deleted = true;
                }
                diagnostic.log(format!("deleted shadow copy id={}", shadow_copy.id))?;
            }
        } else {
            diagnostic.log(format!(
                "leaving shared shadow copy {} for archive workflow cleanup",
                shadow_copy.id
            ))?;
        }

        let (source_path, output_summary) = copy_result?;

        Ok(CollectedStream {
            source_path,
            source_access_method: "vss_raw_ntfs".to_string(),
            logical_size: output_summary.logical_size,
            source_logical_size: output_summary.source_logical_size,
            output_logical_base: output_summary.output_logical_base,
            bytes_written: output_summary.bytes_written,
            allocated_size_written: output_summary.allocated_size_written,
            sha256: output_summary.sha256,
            sha256_scope: output_summary.sha256_scope,
            output_mode: output_summary.output_mode,
            sparse_holes_preserved: output_summary.sparse_holes_preserved,
            transaction_safe: true,
            shadow_copy: Some(shadow_copy_metadata(
                shadow_copy,
                owns_shadow_copy,
                owns_shadow_copy,
                !owns_shadow_copy,
            )),
            data_runs: output_summary.data_runs,
        })
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

    fn relaunch_elevated(args: &UsnDumpCli, diagnostic: &mut DiagnosticLog) -> Result<()> {
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

    fn build_relaunch_parameters(args: &UsnDumpCli) -> String {
        let mut values = vec![
            "collect-usn-journal".to_string(),
            "--volume".to_string(),
            args.volume.clone(),
            "--out".to_string(),
            args.out.display().to_string(),
            "--mode".to_string(),
            mode_cli_value(args.mode).to_string(),
            "--chunk-size-mib".to_string(),
            args.chunk_size_mib.to_string(),
        ];

        if args.sparse {
            values.push("--sparse".to_string());
        }

        if let Some(metadata) = args.metadata.as_ref() {
            values.push("--metadata".to_string());
            values.push(metadata.display().to_string());
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

    fn chunk_size_bytes(chunk_size_mib: usize) -> Result<usize> {
        chunk_size_mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| anyhow!("--chunk-size-mib value is too large"))
    }

    fn copy_stream(
        source_paths: &[String],
        output_path: &std::path::Path,
        chunk_size: usize,
        usn_journal_data: Option<&UsnJournalMetadata>,
        diagnostic: &mut DiagnosticLog,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<(String, OutputWriteSummary)> {
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create output directory {}", parent.display()))?;
        }

        let mut failures = Vec::new();

        for source_path in source_paths {
            emit_progress(
                reporter,
                0.24,
                format!("Opening live USN stream {source_path}."),
                "Opening stream".to_string(),
            );
            diagnostic.log(format!("trying direct-stream path={source_path}"))?;
            match copy_stream_from_path(
                source_path,
                output_path,
                chunk_size,
                usn_journal_data,
                reporter,
            ) {
                Ok(output_summary) => {
                    diagnostic.log(format!(
                        "direct-stream path succeeded path={} logical_size={} bytes_written={} output_mode={:?}",
                        source_path,
                        output_summary.logical_size,
                        output_summary.bytes_written,
                        output_summary.output_mode
                    ))?;
                    return Ok((source_path.clone(), output_summary));
                }
                Err(error) => {
                    diagnostic.log(format!(
                        "direct-stream path failed path={} error={error:#}",
                        source_path
                    ))?;
                    failures.push(format!("{}: {:#}", source_path, error));
                }
            }
        }

        bail!(
            "all direct-stream access attempts failed: {}",
            failures.join("; ")
        )
    }

    fn copy_stream_from_path(
        source_path: &str,
        output_path: &std::path::Path,
        chunk_size: usize,
        usn_journal_data: Option<&UsnJournalMetadata>,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<OutputWriteSummary> {
        let mut input = open_source_stream(source_path)?;
        let source_logical_size = input
            .metadata()
            .with_context(|| format!("read metadata for {}", source_path))?
            .len();
        let mut output = File::create(output_path)
            .with_context(|| format!("create output {}", output_path.display()))?;
        let active_window = active_window_range(usn_journal_data, source_logical_size);
        if let Some(window) = active_window {
            emit_progress(
                reporter,
                0.26,
                format!("Copying active USN window from {source_path}."),
                format_bytes_progress(0, Some(window.length)),
            );
            input
                .seek(SeekFrom::Start(window.logical_offset_base))
                .with_context(|| format!("seek {} to active USN window start", source_path))?;
            return write_active_window_reader(
                &mut input,
                &mut output,
                chunk_size,
                output_path,
                window,
                source_logical_size,
                reporter,
            );
        }

        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; chunk_size];
        let mut bytes_written = 0u64;
        let mut progress = CopyProgressTracker::default();

        loop {
            let bytes_read = input
                .read(&mut buffer)
                .with_context(|| format!("read {}", source_path))?;
            if bytes_read == 0 {
                break;
            }
            output
                .write_all(&buffer[..bytes_read])
                .with_context(|| format!("write {}", output_path.display()))?;
            hasher.update(&buffer[..bytes_read]);
            bytes_written += bytes_read as u64;
            emit_copy_progress(
                reporter,
                &mut progress,
                0.26,
                0.64,
                &format!("Copying USN stream from {source_path}."),
                bytes_written,
                source_logical_size,
            );
        }

        output
            .flush()
            .with_context(|| format!("flush {}", output_path.display()))?;

        Ok(OutputWriteSummary {
            logical_size: source_logical_size,
            source_logical_size: None,
            output_logical_base: 0,
            bytes_written,
            allocated_size_written: bytes_written,
            sha256: format!("{:x}", hasher.finalize()),
            sha256_scope: Some(Sha256Scope::LogicalStream),
            output_mode: OutputMode::DenseLogical,
            sparse_holes_preserved: false,
            data_runs: Vec::new(),
        })
    }

    fn copy_stream_from_raw_ntfs_device_paths(
        device_paths: &[String],
        output_path: &Path,
        chunk_size: usize,
        sparse_output: bool,
        state: &mut CollectionState,
        diagnostic: &mut DiagnosticLog,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<(String, OutputWriteSummary)> {
        let mut failures = Vec::new();

        for device_path in device_paths {
            state.source_path = Some(device_path.clone());
            state.source_access_method = Some("vss_raw_ntfs".to_string());
            state.set_stage("open_vss_raw_device");
            emit_progress(
                reporter,
                0.32,
                format!("Opening raw NTFS view {device_path}."),
                "Opening raw view".to_string(),
            );
            diagnostic.log(format!("trying raw NTFS device path={device_path}"))?;
            match copy_stream_from_raw_ntfs_device(
                device_path,
                output_path,
                chunk_size,
                sparse_output,
                state,
                diagnostic,
                reporter,
            ) {
                Ok(output_summary) => {
                    diagnostic.log(format!(
                        "raw NTFS device path succeeded path={} logical_size={} bytes_written={} output_mode={:?}",
                        device_path,
                        output_summary.logical_size,
                        output_summary.bytes_written,
                        output_summary.output_mode
                    ))?;
                    return Ok((device_path.clone(), output_summary));
                }
                Err(error) => {
                    diagnostic.log(format!(
                        "raw NTFS device path failed path={} error={error:#}",
                        device_path
                    ))?;
                    failures.push(format!("{}: {:#}", device_path, error));
                }
            }
        }

        bail!(
            "all raw NTFS device access attempts failed: {}",
            failures.join("; ")
        )
    }

    fn copy_stream_from_raw_ntfs_device(
        device_path: &str,
        output_path: &Path,
        chunk_size: usize,
        sparse_output: bool,
        state: &mut CollectionState,
        diagnostic: &mut DiagnosticLog,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<OutputWriteSummary> {
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create output directory {}", parent.display()))?;
        }

        state.set_stage("open_vss_raw_device");
        emit_progress(
            reporter,
            0.34,
            format!("Opening raw NTFS device {device_path}."),
            "Raw device".to_string(),
        );
        let raw_device = open_raw_ntfs_device(device_path)?;
        diagnostic.log(format!("opened raw NTFS device path={device_path}"))?;

        let sector_reader = SectorReader::new(raw_device, 4096)
            .with_context(|| format!("wrap raw NTFS device {} in sector reader", device_path))?;
        let mut fs = BufReader::new(sector_reader);
        state.set_stage("parse_vss_raw_ntfs");
        emit_progress(
            reporter,
            0.38,
            "Parsing NTFS metadata from the snapshot.".to_string(),
            "NTFS metadata".to_string(),
        );
        let mut ntfs = Ntfs::new(&mut fs)
            .with_context(|| format!("parse NTFS boot sector from {}", device_path))?;
        ntfs.read_upcase_table(&mut fs)
            .with_context(|| format!("read NTFS $UpCase from {}", device_path))?;
        diagnostic.log(format!(
            "parsed raw NTFS device path={} sector_size={} cluster_size={} file_record_size={} mft_position=0x{:X} serial={:016X}",
            device_path,
            ntfs.sector_size(),
            ntfs.cluster_size(),
            ntfs.file_record_size(),
            ntfs.mft_position().value().map(|value| value.get()).unwrap_or(0),
            ntfs.serial_number()
        ))?;

        let root_directory = ntfs
            .root_directory(&mut fs)
            .with_context(|| format!("open NTFS root directory from {}", device_path))?;
        state.set_stage("find_extend_directory");
        emit_progress(
            reporter,
            0.42,
            "Locating $Extend\\$UsnJrnl:$J inside the snapshot.".to_string(),
            "Resolving stream".to_string(),
        );
        let extend_directory = find_child_file(&ntfs, &mut fs, &root_directory, "root", "$Extend")?;
        state.set_stage("find_usn_journal_file");
        let usn_file = find_child_file(&ntfs, &mut fs, &extend_directory, "$Extend", "$UsnJrnl")?;

        state.set_stage("find_j_data_stream");
        let data_item = usn_file
            .data(&mut fs, "$J")
            .transpose()
            .with_context(|| format!("locate $DATA:$J on {}", device_path))?
            .ok_or_else(|| anyhow!("$UsnJrnl does not contain a named $DATA:$J attribute"))?;
        let data_attribute = data_item
            .to_attribute()
            .with_context(|| format!("open $DATA:$J attribute on {}", device_path))?;

        if data_attribute.ty()? != NtfsAttributeType::Data {
            bail!("resolved attribute is not a $DATA attribute");
        }

        diagnostic.log(format!(
            "resolved $Extend\\$UsnJrnl:$J on raw NTFS device path={} resident={} logical_size={}",
            device_path,
            data_attribute.is_resident(),
            data_attribute.value_length()
        ))?;

        state.set_stage("copy_vss_raw_ntfs_stream");
        emit_progress(
            reporter,
            0.46,
            "Streaming USN Journal bytes from the VSS snapshot.".to_string(),
            format_bytes_progress(0, Some(data_attribute.value_length())),
        );
        let data_value = data_attribute
            .value(&mut fs)
            .with_context(|| format!("read $DATA:$J value from {}", device_path))?;
        let source_logical_size = data_value.len();
        let active_window = if sparse_output {
            None
        } else {
            active_window_range(state.usn_journal_data.as_ref(), source_logical_size)
        };
        let mut output = File::create(output_path)
            .with_context(|| format!("create output {}", output_path.display()))?;
        let output_summary = if sparse_output {
            diagnostic.log(format!(
                "writing sparse logical output for raw NTFS path={} cluster_size={}",
                device_path,
                ntfs.cluster_size()
            ))?;
            write_sparse_attribute_value(
                &mut fs,
                data_value,
                &mut output,
                ntfs.cluster_size() as usize,
                chunk_size,
                output_path,
                reporter,
            )?
        } else if let Some(window) = active_window {
            diagnostic.log(format!(
                "writing active-window output for raw NTFS path={} base_offset={} window_length={} source_logical_size={}"
                ,
                device_path,
                window.logical_offset_base,
                window.length,
                source_logical_size
            ))?;
            write_active_window_attribute_value(
                &mut fs,
                data_value,
                &mut output,
                chunk_size,
                output_path,
                window,
                source_logical_size,
                reporter,
            )?
        } else {
            write_dense_attribute_value(
                &mut fs,
                data_value,
                &mut output,
                chunk_size,
                output_path,
                reporter,
            )?
        };

        diagnostic.log(format!(
            "raw NTFS writer completed path={} output_mode={:?} logical_size={} allocated_size_written={} data_runs={}"
            ,
            device_path,
            output_summary.output_mode,
            output_summary.logical_size,
            output_summary.allocated_size_written,
            output_summary.data_runs.len()
        ))?;

        Ok(output_summary)
    }

    fn write_dense_attribute_value<T>(
        fs: &mut T,
        mut data_value: NtfsAttributeValue<'_, '_>,
        output: &mut File,
        chunk_size: usize,
        output_path: &Path,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<OutputWriteSummary>
    where
        T: Read + Seek,
    {
        let logical_size = data_value.len();
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; chunk_size];
        let mut bytes_written = 0u64;
        let mut progress = CopyProgressTracker::default();

        loop {
            let bytes_read = data_value.read(fs, &mut buffer).with_context(|| {
                format!(
                    "read logical attribute bytes into {}",
                    output_path.display()
                )
            })?;
            if bytes_read == 0 {
                break;
            }

            output
                .write_all(&buffer[..bytes_read])
                .with_context(|| format!("write {}", output_path.display()))?;
            hasher.update(&buffer[..bytes_read]);
            bytes_written += bytes_read as u64;
            emit_copy_progress(
                reporter,
                &mut progress,
                0.46,
                0.46,
                "Copying USN stream from the snapshot.",
                bytes_written,
                logical_size,
            );
        }

        output
            .flush()
            .with_context(|| format!("flush {}", output_path.display()))?;

        Ok(OutputWriteSummary {
            logical_size,
            source_logical_size: None,
            output_logical_base: 0,
            bytes_written,
            allocated_size_written: bytes_written,
            sha256: format!("{:x}", hasher.finalize()),
            sha256_scope: Some(Sha256Scope::LogicalStream),
            output_mode: OutputMode::DenseLogical,
            sparse_holes_preserved: false,
            data_runs: Vec::new(),
        })
    }

    fn write_active_window_reader<T>(
        input: &mut T,
        output: &mut File,
        chunk_size: usize,
        output_path: &Path,
        active_window: ActiveWindowRange,
        source_logical_size: u64,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<OutputWriteSummary>
    where
        T: Read,
    {
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; chunk_size];
        let mut bytes_written = 0u64;
        let mut remaining = active_window.length;
        let mut progress = CopyProgressTracker::default();

        while remaining > 0 {
            let bytes_to_read = usize::min(buffer.len(), remaining as usize);
            let bytes_read = input.read(&mut buffer[..bytes_to_read]).with_context(|| {
                format!("read active USN window into {}", output_path.display())
            })?;
            if bytes_read == 0 {
                bail!("encountered a short read while collecting the active USN window");
            }

            output
                .write_all(&buffer[..bytes_read])
                .with_context(|| format!("write {}", output_path.display()))?;
            hasher.update(&buffer[..bytes_read]);
            bytes_written += bytes_read as u64;
            remaining -= bytes_read as u64;
            emit_copy_progress(
                reporter,
                &mut progress,
                0.26,
                0.64,
                "Copying the active USN window.",
                bytes_written,
                active_window.length,
            );
        }

        output
            .flush()
            .with_context(|| format!("flush {}", output_path.display()))?;

        Ok(OutputWriteSummary {
            logical_size: active_window.length,
            source_logical_size: Some(source_logical_size),
            output_logical_base: active_window.logical_offset_base,
            bytes_written,
            allocated_size_written: bytes_written,
            sha256: format!("{:x}", hasher.finalize()),
            sha256_scope: Some(Sha256Scope::LogicalStream),
            output_mode: OutputMode::ActiveWindow,
            sparse_holes_preserved: false,
            data_runs: Vec::new(),
        })
    }

    fn write_active_window_attribute_value<T>(
        fs: &mut T,
        mut data_value: NtfsAttributeValue<'_, '_>,
        output: &mut File,
        chunk_size: usize,
        output_path: &Path,
        active_window: ActiveWindowRange,
        source_logical_size: u64,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<OutputWriteSummary>
    where
        T: Read + Seek,
    {
        data_value
            .seek(fs, SeekFrom::Start(active_window.logical_offset_base))
            .with_context(|| format!("seek active USN window in {}", output_path.display()))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; chunk_size];
        let mut bytes_written = 0u64;
        let mut remaining = active_window.length;
        let mut progress = CopyProgressTracker::default();

        while remaining > 0 {
            let bytes_to_read = usize::min(buffer.len(), remaining as usize);
            let bytes_read = data_value
                .read(fs, &mut buffer[..bytes_to_read])
                .with_context(|| {
                    format!("read active USN window into {}", output_path.display())
                })?;
            if bytes_read == 0 {
                bail!("encountered a short read while collecting the active USN window");
            }

            output
                .write_all(&buffer[..bytes_read])
                .with_context(|| format!("write {}", output_path.display()))?;
            hasher.update(&buffer[..bytes_read]);
            bytes_written += bytes_read as u64;
            remaining -= bytes_read as u64;
            emit_copy_progress(
                reporter,
                &mut progress,
                0.46,
                0.46,
                "Copying the active USN window from the snapshot.",
                bytes_written,
                active_window.length,
            );
        }

        output
            .flush()
            .with_context(|| format!("flush {}", output_path.display()))?;

        Ok(OutputWriteSummary {
            logical_size: active_window.length,
            source_logical_size: Some(source_logical_size),
            output_logical_base: active_window.logical_offset_base,
            bytes_written,
            allocated_size_written: bytes_written,
            sha256: format!("{:x}", hasher.finalize()),
            sha256_scope: Some(Sha256Scope::LogicalStream),
            output_mode: OutputMode::ActiveWindow,
            sparse_holes_preserved: false,
            data_runs: Vec::new(),
        })
    }

    fn write_sparse_attribute_value<T>(
        fs: &mut T,
        data_value: NtfsAttributeValue<'_, '_>,
        output: &mut File,
        cluster_size: usize,
        chunk_size: usize,
        output_path: &Path,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<OutputWriteSummary>
    where
        T: Read + Seek,
    {
        if cluster_size == 0 {
            bail!("NTFS cluster size must be greater than zero for sparse output");
        }

        mark_file_sparse(output)?;

        match data_value {
            NtfsAttributeValue::NonResident(data_value) => {
                write_sparse_non_resident_attribute_value(
                    fs,
                    data_value,
                    output,
                    chunk_size,
                    output_path,
                    reporter,
                )
            }
            data_value => write_sparse_attribute_value_clustered(
                fs,
                data_value,
                output,
                chunk_size,
                output_path,
                reporter,
            ),
        }
    }

    fn write_sparse_non_resident_attribute_value<T>(
        fs: &mut T,
        data_value: ntfs::attribute_value::NtfsNonResidentAttributeValue<'_, '_>,
        output: &mut File,
        chunk_size: usize,
        output_path: &Path,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<OutputWriteSummary>
    where
        T: Read + Seek,
    {
        let logical_size = data_value.len();
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; chunk_size];
        let mut bytes_written = 0u64;
        let mut logical_offset = 0u64;
        let mut data_runs = Vec::new();
        let mut progress = CopyProgressTracker::default();

        for data_run in data_value.data_runs() {
            let mut data_run = data_run.with_context(|| {
                format!("iterate sparse data runs for {}", output_path.display())
            })?;
            if logical_offset >= logical_size {
                break;
            }

            let run_length = data_run.allocated_size().min(logical_size - logical_offset);
            let volume_offset = data_run
                .data_position()
                .value()
                .map(std::num::NonZeroU64::get);
            let is_sparse = volume_offset.is_none();
            extend_data_runs(
                &mut data_runs,
                logical_offset,
                volume_offset,
                run_length,
                is_sparse,
            );

            if is_sparse {
                output
                    .seek(SeekFrom::Current(
                        i64::try_from(run_length)
                            .context("sparse run length exceeds seek range")?,
                    ))
                    .with_context(|| format!("seek sparse hole in {}", output_path.display()))?;
            } else {
                let mut remaining = run_length;
                while remaining > 0 {
                    let bytes_to_read = usize::min(buffer.len(), remaining as usize);
                    let bytes_read = data_run
                        .read(fs, &mut buffer[..bytes_to_read])
                        .with_context(|| {
                            format!("read sparse data run bytes into {}", output_path.display())
                        })?;
                    if bytes_read == 0 {
                        bail!("encountered a short NTFS data run while writing sparse output");
                    }

                    output.write_all(&buffer[..bytes_read]).with_context(|| {
                        format!("write sparse extent to {}", output_path.display())
                    })?;
                    hasher.update(&buffer[..bytes_read]);
                    bytes_written += bytes_read as u64;
                    remaining -= bytes_read as u64;
                }
            }

            logical_offset += run_length;
            emit_copy_progress(
                reporter,
                &mut progress,
                0.46,
                0.46,
                "Copying sparse USN ranges from the snapshot.",
                logical_offset,
                logical_size,
            );
        }

        output
            .set_len(logical_size)
            .with_context(|| format!("set sparse logical size on {}", output_path.display()))?;
        output
            .flush()
            .with_context(|| format!("flush {}", output_path.display()))?;

        Ok(OutputWriteSummary {
            logical_size,
            source_logical_size: None,
            output_logical_base: 0,
            bytes_written,
            allocated_size_written: bytes_written,
            sha256: format!("{:x}", hasher.finalize()),
            sha256_scope: Some(Sha256Scope::AllocatedRanges),
            output_mode: OutputMode::SparseLogical,
            sparse_holes_preserved: true,
            data_runs,
        })
    }

    fn write_sparse_attribute_value_clustered<T>(
        fs: &mut T,
        mut data_value: NtfsAttributeValue<'_, '_>,
        output: &mut File,
        chunk_size: usize,
        output_path: &Path,
        reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<OutputWriteSummary>
    where
        T: Read + Seek,
    {
        let logical_size = data_value.len();
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; chunk_size];
        let mut bytes_written = 0u64;
        let mut logical_offset = 0u64;
        let mut data_runs = Vec::new();
        let mut progress = CopyProgressTracker::default();

        while logical_offset < logical_size {
            let current_position = data_value
                .data_position()
                .value()
                .map(std::num::NonZeroU64::get);
            let is_sparse = current_position.is_none();
            let run_length = measure_extent_length(
                fs,
                &data_value,
                logical_size - logical_offset,
                current_position,
            )
            .with_context(|| {
                format!("measure sparse extent length for {}", output_path.display())
            })?;
            if run_length == 0 {
                break;
            }

            extend_data_runs(
                &mut data_runs,
                logical_offset,
                current_position,
                run_length,
                is_sparse,
            );

            if is_sparse {
                data_value
                    .seek(
                        fs,
                        SeekFrom::Current(
                            i64::try_from(run_length)
                                .context("sparse run length exceeds seek range")?,
                        ),
                    )
                    .with_context(|| {
                        format!(
                            "advance sparse attribute reader for {}",
                            output_path.display()
                        )
                    })?;
                output
                    .seek(SeekFrom::Current(
                        i64::try_from(run_length)
                            .context("sparse run length exceeds seek range")?,
                    ))
                    .with_context(|| format!("seek sparse hole in {}", output_path.display()))?;
            } else {
                let mut remaining = run_length;
                while remaining > 0 {
                    let bytes_to_read = usize::min(buffer.len(), remaining as usize);
                    let bytes_read = data_value
                        .read(fs, &mut buffer[..bytes_to_read])
                        .with_context(|| {
                            format!(
                                "read sparse logical extent bytes into {}",
                                output_path.display()
                            )
                        })?;
                    if bytes_read == 0 {
                        bail!("encountered a short sparse extent while writing output");
                    }

                    output.write_all(&buffer[..bytes_read]).with_context(|| {
                        format!("write sparse extent to {}", output_path.display())
                    })?;
                    hasher.update(&buffer[..bytes_read]);
                    bytes_written += bytes_read as u64;
                    remaining -= bytes_read as u64;
                }
            }

            logical_offset += run_length;
            emit_copy_progress(
                reporter,
                &mut progress,
                0.46,
                0.46,
                "Copying sparse USN ranges from the snapshot.",
                logical_offset,
                logical_size,
            );
        }

        output
            .set_len(logical_size)
            .with_context(|| format!("set sparse logical size on {}", output_path.display()))?;
        output
            .flush()
            .with_context(|| format!("flush {}", output_path.display()))?;

        Ok(OutputWriteSummary {
            logical_size,
            source_logical_size: None,
            output_logical_base: 0,
            bytes_written,
            allocated_size_written: bytes_written,
            sha256: format!("{:x}", hasher.finalize()),
            sha256_scope: Some(Sha256Scope::AllocatedRanges),
            output_mode: OutputMode::SparseLogical,
            sparse_holes_preserved: true,
            data_runs,
        })
    }

    fn measure_extent_length<T>(
        fs: &mut T,
        data_value: &NtfsAttributeValue<'_, '_>,
        max_length: u64,
        current_position: Option<u64>,
    ) -> Result<u64>
    where
        T: Read + Seek,
    {
        if max_length == 0 {
            return Ok(0);
        }

        let mut lower = 1u64;
        let mut upper = 1u64;
        while upper < max_length && extent_matches(fs, data_value, upper, current_position)? {
            lower = upper;
            upper = (upper.saturating_mul(2)).min(max_length);
        }

        if upper == lower {
            return Ok(lower);
        }

        let mut left = lower;
        let mut right = upper;
        while left < right {
            let mid = left + ((right - left + 1) / 2);
            if extent_matches(fs, data_value, mid, current_position)? {
                left = mid;
            } else {
                right = mid - 1;
            }
        }

        Ok(left)
    }

    fn extent_matches<T>(
        fs: &mut T,
        data_value: &NtfsAttributeValue<'_, '_>,
        candidate_length: u64,
        current_position: Option<u64>,
    ) -> Result<bool>
    where
        T: Read + Seek,
    {
        let mut probe = data_value.clone();
        probe
            .seek(
                fs,
                SeekFrom::Current(
                    i64::try_from(candidate_length - 1)
                        .context("extent probe length exceeds seek range")?,
                ),
            )
            .context("seek sparse extent probe")?;

        let probe_position = probe.data_position().value().map(std::num::NonZeroU64::get);

        match current_position {
            Some(start) => Ok(probe_position == start.checked_add(candidate_length - 1)),
            None => Ok(probe_position.is_none()),
        }
    }

    fn extend_data_runs(
        data_runs: &mut Vec<DataRunMetadata>,
        logical_offset: u64,
        volume_offset: Option<u64>,
        length: u64,
        sparse: bool,
    ) {
        if let Some(previous) = data_runs.last_mut() {
            let logical_contiguous = previous.logical_offset + previous.length == logical_offset;
            let volume_contiguous = match (previous.volume_offset, volume_offset) {
                (None, None) => true,
                (Some(previous_offset), Some(current_offset)) => {
                    previous_offset + previous.length == current_offset
                }
                _ => false,
            };

            if previous.sparse == sparse && logical_contiguous && volume_contiguous {
                previous.length += length;
                return;
            }
        }

        data_runs.push(DataRunMetadata {
            logical_offset,
            volume_offset,
            length,
            sparse,
        });
    }

    fn mark_file_sparse(file: &File) -> Result<()> {
        let handle = HANDLE(file.as_raw_handle() as *mut c_void);
        let mut bytes_returned = 0u32;
        unsafe {
            DeviceIoControl(
                handle,
                FSCTL_SET_SPARSE,
                None,
                0,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        }
        .context("mark output file as sparse")?;
        Ok(())
    }

    fn build_failure_metadata(
        args: &UsnDumpCli,
        volume: &str,
        elevated: bool,
        state: &CollectionState,
        error: &anyhow::Error,
    ) -> UsnDumpMetadata {
        let bytes_written = args
            .out
            .metadata()
            .map(|metadata| metadata.len())
            .unwrap_or(0);

        UsnDumpMetadata {
            metadata_schema: USN_METADATA_SCHEMA.to_string(),
            artifact_type: "ntfs_usn_journal_raw_stream".to_string(),
            artifact_name: r"$Extend\$UsnJrnl:$J".to_string(),
            volume: volume.to_string(),
            source: state.source_path.clone().unwrap_or_default(),
            source_access_method: state
                .source_access_method
                .clone()
                .unwrap_or_else(|| mode_cli_value(args.mode).replace('-', "_")),
            collection_status: CollectionStatus::Failed,
            failure_stage: state.failure_stage.clone(),
            error: Some(CollectionErrorMetadata {
                code: raw_os_error_code(error),
                message: format!("{error:#}"),
            }),
            collection_time_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            elevation: elevated,
            privileges_enabled: state.privileges_enabled.clone(),
            raw_output_produced: bytes_written > 0,
            collector: CollectorMetadata {
                name: "holo-forensics".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                language: "rust".to_string(),
            },
            mode: args.mode,
            output_mode: if args.sparse {
                OutputMode::SparseLogical
            } else if state.usn_journal_data.is_some() {
                OutputMode::ActiveWindow
            } else {
                OutputMode::DenseLogical
            },
            transaction_safe: matches!(
                args.mode,
                UsnDumpMode::VssSnapshot | UsnDumpMode::VssRawNtfs
            ),
            journal_is_circular: true,
            logical_size: 0,
            source_logical_size: None,
            output_logical_base: 0,
            bytes_written,
            allocated_size_written: bytes_written,
            sparse_holes_preserved: false,
            sha256: String::new(),
            sha256_scope: None,
            volume_serial_number: state
                .volume_info
                .as_ref()
                .map(|value| value.serial_number.clone()),
            file_system_type: state
                .volume_info
                .as_ref()
                .map(|value| value.file_system_name.clone()),
            usn_journal_data: state.usn_journal_data.clone(),
            shadow_copy: state.shadow_copy.clone(),
            data_runs: Vec::new(),
            warnings: state.warnings.clone(),
        }
    }

    fn write_failure_artifact(
        args: &UsnDumpCli,
        volume: &str,
        metadata_path: &Path,
        elevated: bool,
        state: &CollectionState,
        error: &anyhow::Error,
        diagnostic: &mut DiagnosticLog,
    ) {
        let failure_metadata = build_failure_metadata(args, volume, elevated, state, error);
        match write_metadata(metadata_path, &failure_metadata) {
            Ok(()) => {
                let _ = diagnostic.log(format!(
                    "failure metadata written to {}",
                    metadata_path.display()
                ));
            }
            Err(write_error) => {
                let _ = diagnostic.log(format!(
                    "could not write failure metadata {}: {write_error:#}",
                    metadata_path.display()
                ));
            }
        }
        let _ = diagnostic.log(format!("collector failed: {error:#}"));
    }

    fn raw_os_error_code(error: &anyhow::Error) -> Option<i32> {
        error
            .chain()
            .find_map(|source| source.downcast_ref::<std::io::Error>())
            .and_then(|io_error| io_error.raw_os_error())
    }

    fn open_source_stream(source_path: &str) -> Result<File> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);
        options.custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN).0);
        options
            .open(source_path)
            .with_context(|| format!("open {}", source_path))
    }

    fn open_raw_ntfs_device(device_path: &str) -> Result<File> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);
        options.custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN).0);
        options
            .open(device_path)
            .with_context(|| format!("open raw NTFS device {}", device_path))
    }

    fn open_volume(volume: &str) -> Result<File> {
        let volume_path = volume_device_path(volume)?;
        let mut options = OpenOptions::new();
        options.read(true);
        options.share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0);
        options
            .open(&volume_path)
            .with_context(|| format!("open volume {}", volume_path))
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

    fn query_volume_info(volume: &str) -> Result<VolumeInfo> {
        let root_path = volume_root_path(volume)?;
        let root_path_wide = encode_wide(&root_path);
        let mut serial_number = 0u32;
        let mut maximum_component_length = 0u32;
        let mut file_system_flags = 0u32;
        let mut file_system_name = [0u16; 64];

        unsafe {
            GetVolumeInformationW(
                PCWSTR(root_path_wide.as_ptr()),
                None,
                Some(&mut serial_number),
                Some(&mut maximum_component_length),
                Some(&mut file_system_flags),
                Some(&mut file_system_name),
            )
        }
        .with_context(|| format!("query volume information for {}", root_path))?;

        Ok(VolumeInfo {
            serial_number: format!("{:08X}", serial_number),
            file_system_name: decode_wide(&file_system_name),
        })
    }

    fn query_usn_journal(volume: &str) -> Result<UsnJournalMetadata> {
        let volume_handle = open_volume(volume)?;
        let mut journal_data = USN_JOURNAL_DATA_V0::default();
        let mut bytes_returned = 0u32;

        unsafe {
            DeviceIoControl(
                HANDLE(volume_handle.as_raw_handle()),
                FSCTL_QUERY_USN_JOURNAL,
                None,
                0,
                Some((&mut journal_data as *mut USN_JOURNAL_DATA_V0).cast::<c_void>()),
                size_of::<USN_JOURNAL_DATA_V0>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        }
        .with_context(|| format!("query live USN journal metadata for {}", volume))?;

        Ok(UsnJournalMetadata {
            journal_id: journal_data.UsnJournalID.to_string(),
            first_usn: journal_data.FirstUsn.to_string(),
            next_usn: journal_data.NextUsn.to_string(),
            lowest_valid_usn: journal_data.LowestValidUsn.to_string(),
            max_usn: journal_data.MaxUsn.to_string(),
            maximum_size: journal_data.MaximumSize.to_string(),
            allocation_delta: journal_data.AllocationDelta.to_string(),
        })
    }

    fn find_child_file<'n, T>(
        ntfs: &'n Ntfs,
        fs: &mut T,
        directory: &NtfsFile<'n>,
        directory_name: &str,
        child_name: &str,
    ) -> Result<NtfsFile<'n>>
    where
        T: Read + Seek,
    {
        let index = directory
            .directory_index(fs)
            .with_context(|| format!("open NTFS directory index for {}", directory_name))?;
        let mut finder = index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, ntfs, fs, child_name)
            .transpose()
            .with_context(|| format!("find {} in NTFS directory {}", child_name, directory_name))?
            .ok_or_else(|| {
                anyhow!(
                    "NTFS directory {} does not contain child {}",
                    directory_name,
                    child_name
                )
            })?;

        entry
            .to_file(ntfs, fs)
            .with_context(|| format!("open NTFS child {} from {}", child_name, directory_name))
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

    struct SectorReader<R>
    where
        R: Read + Seek,
    {
        inner: R,
        sector_size: usize,
        stream_position: u64,
        temp_buf: Vec<u8>,
    }

    impl<R> SectorReader<R>
    where
        R: Read + Seek,
    {
        fn new(inner: R, sector_size: usize) -> std::io::Result<Self> {
            if !sector_size.is_power_of_two() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "sector_size is not a power of two",
                ));
            }

            Ok(Self {
                inner,
                sector_size,
                stream_position: 0,
                temp_buf: Vec::new(),
            })
        }

        fn align_down_to_sector_size(&self, n: u64) -> u64 {
            n / self.sector_size as u64 * self.sector_size as u64
        }

        fn align_up_to_sector_size(&self, n: u64) -> u64 {
            self.align_down_to_sector_size(n) + self.sector_size as u64
        }
    }

    impl<R> Read for SectorReader<R>
    where
        R: Read + Seek,
    {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let aligned_position = self.align_down_to_sector_size(self.stream_position);
            let start = (self.stream_position - aligned_position) as usize;
            let end = start + buf.len();
            let aligned_bytes_to_read = self.align_up_to_sector_size(end as u64) as usize;

            self.temp_buf.resize(aligned_bytes_to_read, 0);
            self.inner.read_exact(&mut self.temp_buf)?;
            buf.copy_from_slice(&self.temp_buf[start..end]);
            self.stream_position += buf.len() as u64;
            Ok(buf.len())
        }
    }

    impl<R> Seek for SectorReader<R>
    where
        R: Read + Seek,
    {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            let new_pos = match pos {
                SeekFrom::Start(n) => Some(n),
                SeekFrom::End(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "SeekFrom::End is unsupported for SectorReader",
                    ));
                }
                SeekFrom::Current(n) => {
                    if n >= 0 {
                        self.stream_position.checked_add(n as u64)
                    } else {
                        self.stream_position.checked_sub(n.wrapping_neg() as u64)
                    }
                }
            };

            match new_pos {
                Some(n) => {
                    let aligned_n = self.align_down_to_sector_size(n);
                    self.inner.seek(SeekFrom::Start(aligned_n))?;
                    self.stream_position = n;
                    Ok(self.stream_position)
                }
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid seek to a negative or overflowing position",
                )),
            }
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

    use super::{UsnDumpCli, UsnProgress, vss};

    pub fn run_with_progress(
        _args: &UsnDumpCli,
        _shared_shadow_copy: Option<&vss::ShadowCopy>,
        _reporter: &mut dyn FnMut(UsnProgress),
    ) -> Result<()> {
        bail!("USN journal collection is only supported on Windows hosts")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        UsnDumpCli, UsnDumpMode, UsnJournalMetadata, active_window_range,
        default_diagnostic_log_path, default_metadata_path, mode_cli_value, normalize_volume,
        shadow_copy_raw_device_paths, shadow_copy_source_path, stream_source_path,
        stream_source_paths, validate_args, volume_device_path, volume_root_path,
    };

    #[test]
    fn normalize_volume_accepts_common_drive_inputs() {
        assert_eq!(normalize_volume("c").unwrap(), "C:");
        assert_eq!(normalize_volume("C:").unwrap(), "C:");
        assert_eq!(normalize_volume(r"\\?\c:").unwrap(), "C:");
        assert_eq!(normalize_volume(r"\\.\c:").unwrap(), "C:");
    }

    #[test]
    fn normalize_volume_rejects_invalid_inputs() {
        assert!(normalize_volume("").is_err());
        assert!(normalize_volume("cd").is_err());
        assert!(normalize_volume("1:").is_err());
    }

    #[test]
    fn default_metadata_path_appends_sidecar_suffix() {
        let path = PathBuf::from(r"C:\temp\C_usn_journal_J.bin");
        assert_eq!(
            default_metadata_path(&path),
            PathBuf::from(r"C:\temp\C_usn_journal_J.bin.metadata.json")
        );
    }

    #[test]
    fn default_diagnostic_log_path_resolves_shared_technical_log() {
        let path = PathBuf::from(r"C:\temp\C_usn_journal_J.bin");
        assert_eq!(
            default_diagnostic_log_path(&path),
            crate::runtime_support::technical_log_path()
        );
    }

    #[test]
    fn usn_paths_use_expected_ntfs_locations() {
        assert_eq!(
            stream_source_path("C:").unwrap(),
            r"\\?\C:\$Extend\$UsnJrnl:$J"
        );
        assert_eq!(volume_device_path("C:").unwrap(), r"\\.\C:");
        assert_eq!(volume_root_path("C:").unwrap(), r"C:\");
    }

    #[test]
    fn usn_path_variants_include_both_documented_direct_stream_forms() {
        assert_eq!(
            stream_source_paths("C:").unwrap(),
            vec![
                r"\\?\C:\$Extend\$UsnJrnl:$J".to_string(),
                r"\\.\C:\$Extend\$UsnJrnl:$J".to_string(),
            ]
        );
    }

    #[test]
    fn shadow_copy_path_uses_device_object_root() {
        assert_eq!(
            shadow_copy_source_path(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12").unwrap(),
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12\$Extend\$UsnJrnl:$J"
        );
    }

    #[test]
    fn shadow_copy_raw_device_paths_include_namespace_variants() {
        assert_eq!(
            shadow_copy_raw_device_paths(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12")
                .unwrap(),
            vec![
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12".to_string(),
                r"\\.\GLOBALROOT\Device\HarddiskVolumeShadowCopy12".to_string(),
            ]
        );
    }

    #[test]
    fn mode_cli_value_matches_clap_value() {
        assert_eq!(mode_cli_value(UsnDumpMode::DirectStream), "direct-stream");
        assert_eq!(mode_cli_value(UsnDumpMode::VssSnapshot), "vss-snapshot");
        assert_eq!(mode_cli_value(UsnDumpMode::VssRawNtfs), "vss-raw-ntfs");
    }

    #[test]
    fn validate_args_rejects_sparse_without_raw_ntfs_mode() {
        let args = UsnDumpCli {
            volume: "C:".to_string(),
            out: PathBuf::from(r"C:\temp\C_usn_journal_J.bin"),
            metadata: None,
            mode: UsnDumpMode::VssSnapshot,
            sparse: true,
            chunk_size_mib: 4,
            diagnostic_log: None,
            elevate: false,
        };

        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn active_window_range_uses_first_and_next_usn() {
        let journal = UsnJournalMetadata {
            journal_id: "1".to_string(),
            first_usn: "4096".to_string(),
            next_usn: "8192".to_string(),
            lowest_valid_usn: "0".to_string(),
            max_usn: "0".to_string(),
            maximum_size: "0".to_string(),
            allocation_delta: "0".to_string(),
        };

        assert_eq!(
            active_window_range(Some(&journal), 16384),
            Some(super::ActiveWindowRange {
                logical_offset_base: 4096,
                length: 4096,
            })
        );
    }

    #[test]
    fn active_window_range_returns_none_for_full_stream() {
        let journal = UsnJournalMetadata {
            journal_id: "1".to_string(),
            first_usn: "0".to_string(),
            next_usn: "8192".to_string(),
            lowest_valid_usn: "0".to_string(),
            max_usn: "0".to_string(),
            maximum_size: "0".to_string(),
            allocation_delta: "0".to_string(),
        };

        assert_eq!(active_window_range(Some(&journal), 8192), None);
    }
}
