#![allow(dead_code)]

use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{SecondsFormat, Utc};
use clap::{Args, ValueEnum};
use ntfs::attribute_value::NtfsAttributeValue;
use ntfs::{KnownNtfsFileRecordNumber, Ntfs, NtfsAttributeType, NtfsReadSeek};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::collection_metadata;
use crate::collections::windows::{usn_journal, vss};
use crate::runtime_support;

const LOGFILE_COLLECTION_SCHEMA: &str = "windows_logfile_collection_v1";
const LOGFILE_COLLECTOR_NAME: &str = "windows_logfile";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum LogFileAcquisitionMode {
    Vss,
    Raw,
}

impl LogFileAcquisitionMode {
    fn manifest_value(self) -> &'static str {
        match self {
            Self::Vss => "vss",
            Self::Raw => "raw",
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct LogFileCollectCli {
    #[arg(
        long,
        help = "NTFS volume, for example C:",
        required_unless_present = "all_volumes"
    )]
    pub volume: Option<String>,

    #[arg(
        long = "all-volumes",
        help = "Collect $LogFile from all detected NTFS volumes"
    )]
    pub all_volumes: bool,

    #[arg(long, value_enum, default_value_t = LogFileAcquisitionMode::Vss, help = "Acquisition mode; vss is the default")]
    pub mode: LogFileAcquisitionMode,

    #[arg(
        long = "out-dir",
        help = "Output root directory for collected $LogFile artifacts"
    )]
    pub out_dir: PathBuf,

    #[arg(
        long,
        help = "Optional collection manifest path for single-volume collection; defaults to <out-dir>/$metadata/collectors/<volume>/windows_logfile/manifest.json"
    )]
    pub manifest: Option<PathBuf>,

    #[arg(
        long = "collection-log",
        help = "Optional collection log path for single-volume collection; defaults to <out-dir>/$metadata/collectors/<volume>/windows_logfile/collection.log"
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
pub struct LogFileCollectRequest {
    pub volume: String,
    pub out_dir: PathBuf,
    pub mode: LogFileAcquisitionMode,
    pub manifest: Option<PathBuf>,
    pub collection_log: Option<PathBuf>,
    pub diagnostic_log: Option<PathBuf>,
    pub elevate: bool,
}

#[derive(Debug, Clone)]
pub struct LogFileCollectSummary {
    pub volume: String,
    pub output_root: PathBuf,
    pub artifact_path: PathBuf,
    pub sha256_path: PathBuf,
    pub manifest_path: PathBuf,
    pub collection_log_path: PathBuf,
    pub archive_path: String,
    pub sha256: String,
    pub bytes_written: u64,
    pub staged_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct LogFileProgress {
    pub progress_value: f32,
    pub detail: String,
    pub progress_text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CollectionStatus {
    Succeeded,
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
struct NtfsBootMetadata {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    cluster_size: u64,
    mft_lcn: u64,
    mftmirr_lcn: u64,
    mft_record_size: u64,
    clusters_per_index_block: i8,
    volume_serial: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFileDataRunMetadata {
    pub index: usize,
    pub lcn: Option<u64>,
    pub byte_offset: Option<u64>,
    pub allocated_size: u64,
    pub sparse: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidationMetadata {
    first_page_signature: String,
    sampled_pages: usize,
    rstr_pages: usize,
    rcrd_pages: usize,
    expected_log_signature_seen: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogFileCollectionManifest {
    metadata_schema: String,
    artifact_type: String,
    artifact_name: String,
    volume: String,
    filesystem: String,
    collection_mode: String,
    collection_status: CollectionStatus,
    collection_start_utc: String,
    collection_end_utc: String,
    elevation: bool,
    collector: CollectorMetadata,
    source_device: String,
    archive_path: String,
    output_file: String,
    sha256_file: String,
    sha256: String,
    bytes_written: u64,
    ntfs: NtfsBootMetadata,
    logfile_real_size: u64,
    data_runs: Vec<LogFileDataRunMetadata>,
    validation: ValidationMetadata,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    privileges_enabled: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shadow_copy: Option<ShadowCopyMetadata>,
}

#[derive(Debug, Clone)]
struct LogFileExtractionResult {
    source_device: String,
    boot: NtfsBootMetadata,
    logfile_real_size: u64,
    data_runs: Vec<LogFileDataRunMetadata>,
    validation: ValidationMetadata,
    sha256: String,
    bytes_written: u64,
}

#[derive(Debug, Clone)]
struct OutputPaths {
    artifact_archive_path: PathBuf,
    artifact_path: PathBuf,
    sha256_path: PathBuf,
    manifest_path: PathBuf,
    collection_log_path: PathBuf,
}

pub fn run(args: &LogFileCollectCli) -> Result<()> {
    let volumes = if args.all_volumes {
        enumerate_ntfs_volumes()?
    } else {
        vec![
            args.volume
                .clone()
                .ok_or_else(|| anyhow!("--volume is required unless --all-volumes is set"))?,
        ]
    };
    if volumes.is_empty() {
        bail!("no NTFS volumes were found for `$LogFile collection");
    }
    if args.all_volumes && (args.manifest.is_some() || args.collection_log.is_some()) {
        bail!("--manifest and --collection-log are only supported for single-volume collection");
    }

    for volume in volumes {
        let summary = collect(&LogFileCollectRequest {
            volume,
            out_dir: args.out_dir.clone(),
            mode: args.mode,
            manifest: args.manifest.clone(),
            collection_log: args.collection_log.clone(),
            diagnostic_log: args.diagnostic_log.clone(),
            elevate: args.elevate,
        })?;
        println!(
            "Collected {} bytes from {} `$LogFile.",
            summary.bytes_written, summary.volume
        );
        println!("SHA-256: {}", summary.sha256);
        println!("Manifest: {}", summary.manifest_path.display());
    }
    Ok(())
}

pub fn collect(request: &LogFileCollectRequest) -> Result<LogFileCollectSummary> {
    let mut reporter = |_| {};
    collect_with_progress(request, &mut reporter)
}

pub fn collect_with_progress(
    request: &LogFileCollectRequest,
    reporter: &mut dyn FnMut(LogFileProgress),
) -> Result<LogFileCollectSummary> {
    validate_request(request)?;
    let volume = usn_journal::normalize_volume(&request.volume)?;
    let paths = output_paths(request, &volume)?;

    if request.elevate && !is_process_elevated() {
        reporter(LogFileProgress {
            progress_value: 0.03,
            detail: "Waiting for elevation approval.".to_string(),
            progress_text: "UAC".to_string(),
        });
        relaunch_elevated(request)?;
        return load_existing_summary(&volume, &request.out_dir, &paths);
    }

    match request.mode {
        LogFileAcquisitionMode::Vss => {
            let shadow_copy = vss::create_shadow_copy(&volume)?;
            let device_paths = shadow_copy_raw_device_paths(&shadow_copy.device_object)?;
            let result = collect_from_device_paths(
                request,
                &volume,
                &paths,
                &device_paths,
                Some((&shadow_copy, false)),
                reporter,
            );
            let delete_result = vss::delete_shadow_copy(&shadow_copy.id)
                .with_context(|| format!("delete LogFile shadow copy {}", shadow_copy.id));
            match (result, delete_result) {
                (Ok(summary), Ok(())) => {
                    mark_shadow_deleted(&summary.manifest_path)?;
                    Ok(summary)
                }
                (Ok(_), Err(error)) => Err(error),
                (Err(error), Ok(())) => Err(error),
                (Err(error), Err(delete_error)) => Err(error.context(format!(
                    "also failed to delete LogFile shadow copy {}: {delete_error:#}",
                    shadow_copy.id
                ))),
            }
        }
        LogFileAcquisitionMode::Raw => collect_from_device_paths(
            request,
            &volume,
            &paths,
            &[volume_device_path(&volume)?],
            None,
            reporter,
        ),
    }
}

pub fn collect_with_progress_using_shadow_copy(
    request: &LogFileCollectRequest,
    shadow_copy: &vss::ShadowCopy,
    reporter: &mut dyn FnMut(LogFileProgress),
) -> Result<LogFileCollectSummary> {
    validate_request(request)?;
    if !matches!(request.mode, LogFileAcquisitionMode::Vss) {
        bail!("shared shadow-copy LogFile collection requires --mode vss");
    }
    let volume = usn_journal::normalize_volume(&request.volume)?;
    let paths = output_paths(request, &volume)?;
    let device_paths = shadow_copy_raw_device_paths(&shadow_copy.device_object)?;
    collect_from_device_paths(
        request,
        &volume,
        &paths,
        &device_paths,
        Some((shadow_copy, true)),
        reporter,
    )
}

pub fn default_manifest_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_manifest_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_LOGFILE_COLLECTOR,
    )
}

pub fn default_collection_log_path(output_root: &Path, volume: &str) -> Result<PathBuf> {
    collection_metadata::collector_log_path(
        output_root,
        volume,
        collection_metadata::WINDOWS_LOGFILE_COLLECTOR,
    )
}

pub fn default_diagnostic_log_path(_output_root: &Path) -> PathBuf {
    runtime_support::technical_log_path()
}

pub fn artifact_archive_path(volume: &str) -> Result<PathBuf> {
    Ok(
        PathBuf::from(usn_journal::normalize_volume(volume)?.trim_end_matches(':'))
            .join("$LogFile.bin"),
    )
}

fn validate_request(request: &LogFileCollectRequest) -> Result<()> {
    let _ = usn_journal::normalize_volume(&request.volume)?;
    if request.out_dir.as_os_str().is_empty() {
        bail!("--out-dir must not be empty");
    }
    Ok(())
}

fn output_paths(request: &LogFileCollectRequest, volume: &str) -> Result<OutputPaths> {
    let artifact_archive_path = artifact_archive_path(volume)?;
    let artifact_path = request.out_dir.join(&artifact_archive_path);
    let sha256_path = artifact_path.with_file_name("$LogFile.bin.sha256");
    let manifest_path = request
        .manifest
        .clone()
        .unwrap_or(default_manifest_path(&request.out_dir, volume)?);
    let collection_log_path = request
        .collection_log
        .clone()
        .unwrap_or(default_collection_log_path(&request.out_dir, volume)?);
    Ok(OutputPaths {
        artifact_archive_path,
        artifact_path,
        sha256_path,
        manifest_path,
        collection_log_path,
    })
}

fn collect_from_device_paths(
    request: &LogFileCollectRequest,
    volume: &str,
    paths: &OutputPaths,
    device_paths: &[String],
    shadow_copy: Option<(&vss::ShadowCopy, bool)>,
    reporter: &mut dyn FnMut(LogFileProgress),
) -> Result<LogFileCollectSummary> {
    fs::create_dir_all(&request.out_dir)
        .with_context(|| format!("create output root {}", request.out_dir.display()))?;

    let start_time = Utc::now();
    let mut warnings = Vec::new();
    let mut privileges_enabled = Vec::new();
    for privilege in [
        "SeBackupPrivilege",
        "SeManageVolumePrivilege",
        "SeRestorePrivilege",
    ] {
        match enable_privilege(privilege) {
            Ok(()) => privileges_enabled.push(privilege.to_string()),
            Err(error) => warnings.push(format!("could not enable {privilege}: {error:#}")),
        }
    }
    if request.mode == LogFileAcquisitionMode::Raw {
        warnings.push(
            "raw live mode reads a moving NTFS volume and may include inconsistencies".to_string(),
        );
    }

    let mut failures = Vec::new();
    let mut extraction = None;
    for device_path in device_paths {
        reporter(LogFileProgress {
            progress_value: 0.18,
            detail: format!("Opening raw NTFS view {device_path}."),
            progress_text: "Opening raw view".to_string(),
        });
        match extract_logfile_from_device(device_path, &paths.artifact_path, reporter) {
            Ok(result) => {
                extraction = Some(result);
                break;
            }
            Err(error) => failures.push(format!("{}: {:#}", device_path, error)),
        }
    }
    let extraction = extraction.ok_or_else(|| {
        anyhow!(
            "all `$LogFile raw device access attempts failed: {}",
            failures.join("; ")
        )
    })?;
    warnings.extend(failures.into_iter().map(|failure| {
        format!("raw device attempt failed before successful extraction: {failure}")
    }));

    write_sha256_file(
        &paths.sha256_path,
        &extraction.sha256,
        &paths.artifact_archive_path,
    )?;
    let end_time = Utc::now();
    let archive_path = normalize_archive_path_string(&paths.artifact_archive_path);
    let sha256_archive_path = normalize_archive_path_string(
        &paths
            .artifact_archive_path
            .with_file_name("`$LogFile.bin.sha256"),
    );
    let manifest = LogFileCollectionManifest {
        metadata_schema: LOGFILE_COLLECTION_SCHEMA.to_string(),
        artifact_type: "windows_logfile_collection".to_string(),
        artifact_name: "`$LogFile".to_string(),
        volume: volume.to_string(),
        filesystem: "NTFS".to_string(),
        collection_mode: request.mode.manifest_value().to_string(),
        collection_status: CollectionStatus::Succeeded,
        collection_start_utc: start_time.to_rfc3339_opts(SecondsFormat::Nanos, true),
        collection_end_utc: end_time.to_rfc3339_opts(SecondsFormat::Nanos, true),
        elevation: is_process_elevated(),
        collector: CollectorMetadata {
            name: LOGFILE_COLLECTOR_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            language: "rust".to_string(),
        },
        source_device: extraction.source_device.clone(),
        archive_path: archive_path.clone(),
        output_file: archive_path.clone(),
        sha256_file: sha256_archive_path,
        sha256: extraction.sha256.clone(),
        bytes_written: extraction.bytes_written,
        ntfs: extraction.boot.clone(),
        logfile_real_size: extraction.logfile_real_size,
        data_runs: extraction.data_runs.clone(),
        validation: extraction.validation.clone(),
        privileges_enabled,
        warnings,
        shadow_copy: shadow_copy.map(|(copy, shared)| ShadowCopyMetadata {
            created: !shared,
            deleted: false,
            shared,
            id: copy.id.clone(),
            device_object: copy.device_object.clone(),
            context: copy.context.clone(),
        }),
    };
    write_manifest(&paths.manifest_path, &manifest)?;
    write_collection_log(&paths.collection_log_path, &manifest)?;

    reporter(LogFileProgress {
        progress_value: 1.0,
        detail: format!("Collected `$LogFile from {volume}."),
        progress_text: format_bytes(extraction.bytes_written),
    });

    Ok(LogFileCollectSummary {
        volume: volume.to_string(),
        output_root: request.out_dir.clone(),
        artifact_path: paths.artifact_path.clone(),
        sha256_path: paths.sha256_path.clone(),
        manifest_path: paths.manifest_path.clone(),
        collection_log_path: paths.collection_log_path.clone(),
        archive_path,
        sha256: extraction.sha256,
        bytes_written: extraction.bytes_written,
        staged_paths: vec![
            paths.artifact_path.clone(),
            paths.sha256_path.clone(),
            paths.manifest_path.clone(),
            paths.collection_log_path.clone(),
        ],
    })
}

fn extract_logfile_from_device(
    device_path: &str,
    output_path: &Path,
    reporter: &mut dyn FnMut(LogFileProgress),
) -> Result<LogFileExtractionResult> {
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create LogFile output directory {}", parent.display()))?;
    }

    let raw_device = open_raw_ntfs_device(device_path)?;
    let mut fs = SectorReader::new(raw_device, 4096)
        .with_context(|| format!("wrap raw NTFS device {} in sector reader", device_path))?;
    let boot = read_boot_metadata(&mut fs)
        .with_context(|| format!("read NTFS boot sector from {device_path}"))?;
    fs.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind raw NTFS device {}", device_path))?;

    reporter(LogFileProgress {
        progress_value: 0.28,
        detail: "Parsing NTFS metadata and locating $LogFile runs.".to_string(),
        progress_text: "NTFS metadata".to_string(),
    });
    let ntfs =
        Ntfs::new(&mut fs).with_context(|| format!("parse NTFS boot sector from {device_path}"))?;
    let logfile_file = ntfs
        .file(&mut fs, KnownNtfsFileRecordNumber::LogFile as u64)
        .with_context(|| format!("read $LogFile MFT record 2 from {device_path}"))?;
    let file_name = logfile_file
        .name(&mut fs, None, None)
        .transpose()
        .with_context(|| format!("read $LogFile file name from {device_path}"))?
        .ok_or_else(|| anyhow!("$LogFile MFT record did not expose a $FILE_NAME attribute"))?;
    let file_name = file_name.name().to_string_lossy();
    if file_name != "$LogFile" {
        bail!("MFT record 2 resolved to {file_name}, not $LogFile");
    }
    let data_item = logfile_file
        .data(&mut fs, "")
        .transpose()
        .with_context(|| format!("locate unnamed $DATA attribute on $LogFile from {device_path}"))?
        .ok_or_else(|| anyhow!("$LogFile does not contain an unnamed $DATA attribute"))?;
    let data_attribute = data_item
        .to_attribute()
        .with_context(|| format!("open $LogFile unnamed $DATA attribute on {device_path}"))?;
    if data_attribute.ty()? != NtfsAttributeType::Data {
        bail!("resolved $LogFile attribute is not a $DATA attribute");
    }
    let data_value = data_attribute
        .value(&mut fs)
        .with_context(|| format!("read $LogFile unnamed $DATA value from {device_path}"))?;
    let logfile_real_size = data_value.len();
    let data_runs = collect_data_runs(&data_value, boot.cluster_size);

    reporter(LogFileProgress {
        progress_value: 0.38,
        detail: "Streaming $LogFile bytes from raw NTFS runs.".to_string(),
        progress_text: format_bytes_progress(0, Some(logfile_real_size)),
    });
    let (sha256, bytes_written) = write_attribute_value(
        &mut fs,
        data_value,
        output_path,
        1024 * 1024,
        logfile_real_size,
        reporter,
    )?;
    if bytes_written != logfile_real_size {
        bail!(
            "$LogFile output size mismatch: wrote {} bytes but expected {}",
            bytes_written,
            logfile_real_size
        );
    }

    let validation = validate_logfile_output(output_path)?;
    Ok(LogFileExtractionResult {
        source_device: device_path.to_string(),
        boot,
        logfile_real_size,
        data_runs,
        validation,
        sha256,
        bytes_written,
    })
}

fn collect_data_runs(
    value: &NtfsAttributeValue<'_, '_>,
    cluster_size: u64,
) -> Vec<LogFileDataRunMetadata> {
    match value {
        NtfsAttributeValue::NonResident(inner) => inner
            .data_runs()
            .enumerate()
            .filter_map(|(index, run)| {
                let run = run.ok()?;
                let byte_offset = run.data_position().value().map(|value| value.get());
                Some(LogFileDataRunMetadata {
                    index,
                    lcn: byte_offset.map(|offset| offset / cluster_size),
                    byte_offset,
                    allocated_size: run.allocated_size(),
                    sparse: byte_offset.is_none(),
                })
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn write_attribute_value<T>(
    fs: &mut T,
    mut data_value: NtfsAttributeValue<'_, '_>,
    output_path: &Path,
    chunk_size: usize,
    total_size: u64,
    reporter: &mut dyn FnMut(LogFileProgress),
) -> Result<(String, u64)>
where
    T: Read + Seek,
{
    let mut output = File::create(output_path)
        .with_context(|| format!("create output {}", output_path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; chunk_size.max(4096)];
    let mut bytes_written = 0u64;
    loop {
        let bytes_read = data_value
            .read(fs, &mut buffer)
            .with_context(|| format!("read $LogFile bytes into {}", output_path.display()))?;
        if bytes_read == 0 {
            break;
        }
        output
            .write_all(&buffer[..bytes_read])
            .with_context(|| format!("write $LogFile bytes into {}", output_path.display()))?;
        hasher.update(&buffer[..bytes_read]);
        bytes_written += bytes_read as u64;
        reporter(LogFileProgress {
            progress_value: 0.38 + (0.52 * progress_fraction(bytes_written, total_size)),
            detail: "Streaming $LogFile bytes from raw NTFS runs.".to_string(),
            progress_text: format_bytes_progress(bytes_written, Some(total_size)),
        });
    }
    output
        .flush()
        .with_context(|| format!("flush output {}", output_path.display()))?;
    Ok((format!("{:x}", hasher.finalize()), bytes_written))
}

fn read_boot_metadata<T>(reader: &mut T) -> Result<NtfsBootMetadata>
where
    T: Read + Seek,
{
    reader.seek(SeekFrom::Start(0))?;
    let mut sector = [0u8; 512];
    reader.read_exact(&mut sector)?;
    if &sector[3..11] != b"NTFS    " {
        bail!("boot sector OEM ID is not NTFS");
    }
    let bytes_per_sector = u16::from_le_bytes([sector[0x0B], sector[0x0C]]);
    let sectors_per_cluster = sector[0x0D];
    if bytes_per_sector == 0 || sectors_per_cluster == 0 {
        bail!("invalid NTFS sector or cluster geometry");
    }
    let cluster_size = u64::from(bytes_per_sector) * u64::from(sectors_per_cluster);
    let mft_lcn = u64::from_le_bytes(sector[0x30..0x38].try_into()?);
    let mftmirr_lcn = u64::from_le_bytes(sector[0x38..0x40].try_into()?);
    let clusters_per_record = i8::from_le_bytes([sector[0x40]]);
    let mft_record_size = decode_record_size(clusters_per_record, cluster_size)?;
    let clusters_per_index_block = i8::from_le_bytes([sector[0x44]]);
    let volume_serial = u64::from_le_bytes(sector[0x48..0x50].try_into()?);
    if mft_lcn == 0 || mft_record_size == 0 {
        bail!("invalid NTFS $LogFile boot metadata");
    }
    Ok(NtfsBootMetadata {
        bytes_per_sector,
        sectors_per_cluster,
        cluster_size,
        mft_lcn,
        mftmirr_lcn,
        mft_record_size,
        clusters_per_index_block,
        volume_serial: format!("{volume_serial:016X}"),
    })
}

fn decode_record_size(clusters_per_record: i8, cluster_size: u64) -> Result<u64> {
    if clusters_per_record > 0 {
        Ok(clusters_per_record as u64 * cluster_size)
    } else {
        let exponent = clusters_per_record
            .checked_neg()
            .ok_or_else(|| anyhow!("invalid NTFS record size exponent"))?
            as u32;
        Ok(1u64 << exponent)
    }
}

fn validate_logfile_output(path: &Path) -> Result<ValidationMetadata> {
    let mut file = File::open(path).with_context(|| format!("open output {}", path.display()))?;
    let mut page = vec![0u8; 4096];
    let mut sampled_pages = 0usize;
    let mut rstr_pages = 0usize;
    let mut rcrd_pages = 0usize;
    let mut first_signature = String::new();
    for index in 0..64usize {
        match file.read_exact(&mut page) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                return Err(error).with_context(|| format!("read output {}", path.display()));
            }
        }
        let signature = &page[..4.min(page.len())];
        if index == 0 {
            first_signature = String::from_utf8_lossy(signature).to_string();
        }
        sampled_pages += 1;
        if signature == b"RSTR" {
            rstr_pages += 1;
        } else if signature == b"RCRD" {
            rcrd_pages += 1;
        }
    }
    if sampled_pages == 0 {
        bail!("$LogFile output is empty");
    }
    let expected_log_signature_seen = rstr_pages > 0 || rcrd_pages > 0;
    Ok(ValidationMetadata {
        first_page_signature: first_signature,
        sampled_pages,
        rstr_pages,
        rcrd_pages,
        expected_log_signature_seen,
    })
}

fn write_sha256_file(path: &Path, sha256: &str, archive_path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create SHA-256 directory {}", parent.display()))?;
    }
    let mut file =
        File::create(path).with_context(|| format!("create SHA-256 file {}", path.display()))?;
    writeln!(
        file,
        "{}  {}",
        sha256,
        archive_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("$LogFile.bin")
    )?;
    Ok(())
}

fn write_manifest(path: &Path, manifest: &LogFileCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create manifest directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(manifest)?;
    fs::write(path, bytes).with_context(|| format!("write manifest {}", path.display()))
}

fn write_collection_log(path: &Path, manifest: &LogFileCollectionManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create collection log directory {}", parent.display()))?;
    }
    let file = File::create(path).with_context(|| format!("create log {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writeln!(
        writer,
        "LogFile collection volume={} mode={} source={}",
        manifest.volume, manifest.collection_mode, manifest.source_device
    )?;
    writeln!(
        writer,
        "bytes_written={} sha256={} logfile_real_size={}",
        manifest.bytes_written, manifest.sha256, manifest.logfile_real_size
    )?;
    writeln!(
        writer,
        "cluster_size={} mft_lcn={} record_size={} data_runs={}",
        manifest.ntfs.cluster_size,
        manifest.ntfs.mft_lcn,
        manifest.ntfs.mft_record_size,
        manifest.data_runs.len()
    )?;
    for warning in &manifest.warnings {
        writeln!(writer, "warning {warning}")?;
    }
    writer.flush().context("flush LogFile collection log")
}

fn load_existing_summary(
    volume: &str,
    output_root: &Path,
    paths: &OutputPaths,
) -> Result<LogFileCollectSummary> {
    let bytes = fs::read(&paths.manifest_path)
        .with_context(|| format!("read manifest {}", paths.manifest_path.display()))?;
    let manifest: LogFileCollectionManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode manifest {}", paths.manifest_path.display()))?;
    Ok(LogFileCollectSummary {
        volume: volume.to_string(),
        output_root: output_root.to_path_buf(),
        artifact_path: paths.artifact_path.clone(),
        sha256_path: paths.sha256_path.clone(),
        manifest_path: paths.manifest_path.clone(),
        collection_log_path: paths.collection_log_path.clone(),
        archive_path: manifest.archive_path,
        sha256: manifest.sha256,
        bytes_written: manifest.bytes_written,
        staged_paths: vec![
            paths.artifact_path.clone(),
            paths.sha256_path.clone(),
            paths.manifest_path.clone(),
            paths.collection_log_path.clone(),
        ],
    })
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
    Ok(format!(r"\\.\{}", usn_journal::normalize_volume(volume)?))
}

fn progress_fraction(done: u64, total: u64) -> f32 {
    if total == 0 {
        1.0
    } else {
        (done as f32 / total as f32).clamp(0.0, 1.0)
    }
}

fn format_bytes(value: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if value >= MIB {
        format!("{:.1} MiB", value as f64 / MIB as f64)
    } else {
        format!("{} bytes", value)
    }
}

fn format_bytes_progress(done: u64, total: Option<u64>) -> String {
    match total {
        Some(total) => format!("{} / {}", format_bytes(done), format_bytes(total)),
        None => format_bytes(done),
    }
}

fn normalize_archive_path_string(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(target_os = "windows")]
fn open_raw_ntfs_device(device_path: &str) -> Result<File> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_RANDOM_ACCESS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options.read(true);
    options.share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);
    options.custom_flags(FILE_FLAG_RANDOM_ACCESS.0);
    options
        .open(device_path)
        .with_context(|| format!("open raw NTFS device {}", device_path))
}

#[cfg(not(target_os = "windows"))]
fn open_raw_ntfs_device(_device_path: &str) -> Result<File> {
    bail!("raw NTFS device access is only supported on Windows")
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
fn relaunch_elevated(request: &LogFileCollectRequest) -> Result<()> {
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
        .context("launch elevated LogFile collector via UAC")?;
    if execute.hProcess.is_invalid() {
        bail!("UAC launch did not return a process handle to wait on");
    }
    unsafe {
        WaitForSingleObject(execute.hProcess, INFINITE);
    }
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(execute.hProcess, &mut exit_code) }
        .context("read elevated LogFile collector exit code")?;
    let _ = unsafe { CloseHandle(execute.hProcess) };
    if exit_code != 0 {
        bail!("elevated LogFile collector exited with status {exit_code}");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn relaunch_elevated(_request: &LogFileCollectRequest) -> Result<()> {
    bail!("LogFile elevation relaunch is only available on Windows")
}

fn build_relaunch_parameters(request: &LogFileCollectRequest) -> String {
    let mut values = vec![
        "collect-logfile".to_string(),
        "--volume".to_string(),
        request.volume.clone(),
        "--mode".to_string(),
        request.mode.manifest_value().to_string(),
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

#[cfg(target_os = "windows")]
fn enumerate_ntfs_volumes() -> Result<Vec<String>> {
    use windows::Win32::Storage::FileSystem::{
        GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW,
    };
    use windows::core::PCWSTR;

    let mask = unsafe { GetLogicalDrives() };
    if mask == 0 {
        bail!("GetLogicalDrives returned no volumes");
    }
    let mut volumes = Vec::new();
    for index in 0..26u32 {
        if mask & (1 << index) == 0 {
            continue;
        }
        let letter = (b'A' + index as u8) as char;
        let root = format!("{letter}:\\");
        let root_wide = encode_wide(&root);
        let drive_type = unsafe { GetDriveTypeW(PCWSTR(root_wide.as_ptr())) };
        if drive_type != 3 && drive_type != 2 {
            continue;
        }
        let mut file_system_name = [0u16; 64];
        let info_result = unsafe {
            GetVolumeInformationW(
                PCWSTR(root_wide.as_ptr()),
                None,
                None,
                None,
                None,
                Some(&mut file_system_name),
            )
        };
        if info_result.is_err() {
            continue;
        }
        if decode_wide(&file_system_name).eq_ignore_ascii_case("NTFS") {
            volumes.push(format!("{letter}:"));
        }
    }
    Ok(volumes)
}

#[cfg(not(target_os = "windows"))]
fn enumerate_ntfs_volumes() -> Result<Vec<String>> {
    bail!("NTFS volume enumeration is only supported on Windows")
}

#[cfg(target_os = "windows")]
fn decode_wide(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

struct SectorReader<R> {
    inner: R,
    position: u64,
    sector_size: u64,
    temp_buf: Vec<u8>,
}

impl<R> SectorReader<R>
where
    R: Read + Seek,
{
    fn new(inner: R, sector_size: u64) -> Result<Self> {
        if sector_size == 0 {
            bail!("sector size must be greater than zero");
        }
        Ok(Self {
            inner,
            position: 0,
            sector_size,
            temp_buf: Vec::new(),
        })
    }

    fn align_down_to_sector_size(&self, value: u64) -> u64 {
        value - (value % self.sector_size)
    }

    fn align_up_to_sector_size(&self, value: u64) -> u64 {
        if value % self.sector_size == 0 {
            value
        } else {
            value + (self.sector_size - (value % self.sector_size))
        }
    }
}

impl<R> Read for SectorReader<R>
where
    R: Read + Seek,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let aligned_start = self.align_down_to_sector_size(self.position);
        let offset = (self.position - aligned_start) as usize;
        let end = offset + buf.len();
        let aligned_bytes_to_read = self.align_up_to_sector_size(end as u64) as usize;
        self.temp_buf.resize(aligned_bytes_to_read, 0);
        self.inner.seek(SeekFrom::Start(aligned_start))?;
        self.inner.read_exact(&mut self.temp_buf)?;
        buf.copy_from_slice(&self.temp_buf[offset..end]);
        self.position += buf.len() as u64;
        Ok(buf.len())
    }
}

impl<R> Seek for SectorReader<R>
where
    R: Read + Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_position = match pos {
            SeekFrom::Start(value) => value,
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.position.saturating_add(delta as u64)
                } else {
                    self.position.saturating_sub(delta.unsigned_abs())
                }
            }
            SeekFrom::End(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "seeking from end is not supported for raw NTFS devices",
                ));
            }
        };
        self.position = new_position;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::PathBuf;

    use anyhow::Result;

    use super::{
        LogFileAcquisitionMode, artifact_archive_path, decode_record_size,
        default_collection_log_path, default_manifest_path, read_boot_metadata,
        shadow_copy_raw_device_paths,
    };

    #[test]
    fn default_logfile_metadata_paths_live_under_central_collector_root() -> Result<()> {
        let root = PathBuf::from(r"C:\evidence");
        assert_eq!(
            default_manifest_path(&root, "c:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_logfile")
                .join("manifest.json")
        );
        assert_eq!(
            default_collection_log_path(&root, r"\\?\C:")?,
            root.join("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_logfile")
                .join("collection.log")
        );
        Ok(())
    }

    #[test]
    fn logfile_artifact_archive_path_uses_volume_root() -> Result<()> {
        assert_eq!(
            artifact_archive_path("c:")?,
            PathBuf::from("C").join("$LogFile.bin")
        );
        Ok(())
    }

    #[test]
    fn record_size_decoding_matches_ntfs_rules() -> Result<()> {
        assert_eq!(decode_record_size(2, 4096)?, 8192);
        assert_eq!(decode_record_size(-10, 4096)?, 1024);
        Ok(())
    }

    #[test]
    fn boot_metadata_reads_logfile_fields() -> Result<()> {
        let mut sector = [0u8; 512];
        sector[3..11].copy_from_slice(b"NTFS    ");
        sector[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        sector[0x0D] = 8;
        sector[0x30..0x38].copy_from_slice(&786432u64.to_le_bytes());
        sector[0x38..0x40].copy_from_slice(&4u64.to_le_bytes());
        sector[0x40] = (-10i8) as u8;
        sector[0x44] = 1;
        sector[0x48..0x50].copy_from_slice(&0xAABBCCDDEEFF0011u64.to_le_bytes());
        let boot = read_boot_metadata(&mut Cursor::new(sector))?;
        assert_eq!(boot.bytes_per_sector, 512);
        assert_eq!(boot.cluster_size, 4096);
        assert_eq!(boot.mft_lcn, 786432);
        assert_eq!(boot.mft_record_size, 1024);
        assert_eq!(boot.volume_serial, "AABBCCDDEEFF0011");
        Ok(())
    }

    #[test]
    fn shadow_copy_raw_device_paths_include_namespace_variants() -> Result<()> {
        let paths =
            shadow_copy_raw_device_paths(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12")?;
        assert_eq!(
            paths[0],
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12"
        );
        assert_eq!(
            paths[1],
            r"\\.\GLOBALROOT\Device\HarddiskVolumeShadowCopy12"
        );
        Ok(())
    }

    #[test]
    fn mode_manifest_values_are_stable() {
        assert_eq!(LogFileAcquisitionMode::Vss.manifest_value(), "vss");
        assert_eq!(LogFileAcquisitionMode::Raw.manifest_value(), "raw");
    }
}
