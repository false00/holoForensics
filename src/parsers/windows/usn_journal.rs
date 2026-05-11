use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::collection_metadata;
use crate::parser_catalog::ParserFamily;
use crate::parsers::common::{
    Plan, create_output_files, decode_utf16_record, file_name_equals, filetime_to_rfc3339,
    find_paths, new_local_plan, required_root, write_json_line,
};

const USN_ARTIFACT_SUFFIX: &str = "_usn_journal_j.bin";
const USN_ARCHIVE_STREAM_FILE: &str = "$J.bin";
const USN_ARCHIVE_STREAM_PARENT: &str = "$UsnJrnl";
const USN_ARCHIVE_STREAM_GRANDPARENT: &str = "$Extend";
const READ_CHUNK_SIZE: usize = 1024 * 1024;
const USN_RECORD_V2_HEADER_SIZE: usize = 60;
const USN_RECORD_V3_HEADER_SIZE: usize = 76;

#[derive(Debug, Clone, Deserialize, Default)]
struct UsnMetadataSidecar {
    #[serde(default)]
    volume: String,
    #[serde(default)]
    source_access_method: String,
    #[serde(default)]
    output_logical_base: u64,
    #[serde(default)]
    usn_journal_data: Option<UsnJournalData>,
    #[serde(default)]
    data_runs: Vec<UsnDataRun>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct UsnJournalData {
    #[serde(default)]
    first_usn: String,
    #[serde(default)]
    next_usn: String,
}

#[derive(Debug, Clone, Deserialize)]
struct UsnDataRun {
    logical_offset: u64,
    length: u64,
    sparse: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogicalRange {
    start: u64,
    length: u64,
}

pub fn build(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    let paths = find_paths(root, is_usn_journal_artifact)?;
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![new_local_plan(
        family,
        root,
        "Windows.NTFS.UsnJournal.RawStream",
        "windows.usn_journal",
    )])
}

pub fn collect(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let root = required_root(plan)?;
    let paths = find_paths(&root, is_usn_journal_artifact)?;
    let (mut output_file, mut log_file, output_path, log_path) =
        create_output_files(output_dir, &plan.output_name)?;

    let mut records = 0usize;
    for path in &paths {
        match collect_file(&root, &mut output_file, &mut log_file, path) {
            Ok(written) => records += written,
            Err(error) => writeln!(log_file, "skip {}: {error}", path.display())?,
        }
    }

    writeln!(log_file, "files={} records={records}", paths.len())?;
    Ok((output_path, log_path))
}

fn collect_file(
    root: &Path,
    output_file: &mut File,
    log_file: &mut File,
    path: &Path,
) -> Result<usize> {
    let file_len = fs::metadata(path)
        .with_context(|| format!("read metadata for {}", path.display()))?
        .len();
    let metadata = load_sidecar(root, path)?;
    let output_logical_base = metadata
        .as_ref()
        .map(|value| value.output_logical_base)
        .unwrap_or(0);
    let (parse_start, parse_end) = parse_window(metadata.as_ref(), file_len);
    if parse_start >= parse_end {
        return Ok(0);
    }

    let ranges = build_ranges(metadata.as_ref(), parse_start, parse_end);
    let mut input = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buffer = vec![0u8; READ_CHUNK_SIZE];
    let mut pending = Vec::new();
    let mut pending_offset = 0u64;
    let mut records = 0usize;

    for range in ranges {
        if range.length == 0 {
            continue;
        }

        if pending.is_empty() {
            pending_offset = range.start;
        } else if pending_offset + pending.len() as u64 != range.start {
            writeln!(
                log_file,
                "skip {} trailing bytes at offset {} before sparse gap",
                pending.len(),
                output_logical_base.saturating_add(pending_offset)
            )?;
            pending.clear();
            pending_offset = range.start;
        }

        input
            .seek(SeekFrom::Start(range.start))
            .with_context(|| format!("seek {} to {}", path.display(), range.start))?;
        let mut remaining = range.length;
        while remaining > 0 {
            let bytes_to_read = usize::min(buffer.len(), remaining as usize);
            let bytes_read = input
                .read(&mut buffer[..bytes_to_read])
                .with_context(|| format!("read {}", path.display()))?;
            if bytes_read == 0 {
                bail!("unexpected end of file while parsing {}", path.display());
            }

            pending.extend_from_slice(&buffer[..bytes_read]);
            remaining -= bytes_read as u64;
            records += drain_pending_records(
                output_file,
                log_file,
                path,
                &metadata,
                &mut pending,
                &mut pending_offset,
            )?;
        }
    }

    if !pending.is_empty() && pending.iter().any(|byte| *byte != 0) {
        writeln!(
            log_file,
            "skip {} trailing bytes at offset {} after final parse range",
            pending.len(),
            output_logical_base.saturating_add(pending_offset)
        )?;
    }

    Ok(records)
}

fn drain_pending_records(
    output_file: &mut File,
    log_file: &mut File,
    path: &Path,
    metadata: &Option<UsnMetadataSidecar>,
    pending: &mut Vec<u8>,
    pending_offset: &mut u64,
) -> Result<usize> {
    let mut consumed = 0usize;
    let mut records = 0usize;
    let output_logical_base = metadata
        .as_ref()
        .map(|value| value.output_logical_base)
        .unwrap_or(0);

    while pending.len().saturating_sub(consumed) >= 8 {
        let relative_record_offset = *pending_offset + consumed as u64;
        let record_offset = output_logical_base.saturating_add(relative_record_offset);
        let record_length = u32::from_le_bytes(
            pending[consumed..consumed + 4]
                .try_into()
                .expect("record length slice"),
        ) as usize;

        if record_length == 0 {
            let zero_run = pending[consumed..]
                .iter()
                .take_while(|byte| **byte == 0)
                .count();
            if zero_run == pending.len() - consumed {
                consumed = pending.len();
                break;
            }

            if zero_run > 0 {
                writeln!(
                    log_file,
                    "skip {}: {} zero-padding bytes at offset {}",
                    path.display(),
                    zero_run,
                    record_offset
                )?;
                consumed += zero_run;
                continue;
            }

            writeln!(
                log_file,
                "skip {}: zero-length record at offset {}",
                path.display(),
                record_offset
            )?;
            consumed += 8;
            continue;
        }

        if record_length < 8 {
            writeln!(
                log_file,
                "skip {}: invalid record length {} at offset {}",
                path.display(),
                record_length,
                record_offset
            )?;
            consumed += 8;
            continue;
        }

        if pending.len() - consumed < record_length {
            break;
        }

        let record_data = &pending[consumed..consumed + record_length];
        match parse_record(record_data, record_offset, path, metadata.as_ref()) {
            Ok(Some(record)) => {
                write_json_line(output_file, &record)?;
                records += 1;
            }
            Ok(None) => {
                let major_version =
                    u16::from_le_bytes(record_data[4..6].try_into().expect("major version slice"));
                let minor_version =
                    u16::from_le_bytes(record_data[6..8].try_into().expect("minor version slice"));
                writeln!(
                    log_file,
                    "skip {}: unsupported USN record version {}.{} at offset {}",
                    path.display(),
                    major_version,
                    minor_version,
                    record_offset
                )?;
            }
            Err(error) => {
                writeln!(
                    log_file,
                    "skip {}: record at offset {}: {error}",
                    path.display(),
                    record_offset
                )?;
            }
        }

        consumed += record_length;
    }

    if consumed > 0 {
        pending.drain(0..consumed);
        *pending_offset += consumed as u64;
    }

    Ok(records)
}

fn parse_record(
    data: &[u8],
    record_offset: u64,
    path: &Path,
    metadata: Option<&UsnMetadataSidecar>,
) -> Result<Option<Map<String, Value>>> {
    if data.len() < 8 {
        bail!("record shorter than USN header");
    }

    let record_length = u32::from_le_bytes(data[0..4].try_into()?) as usize;
    if record_length != data.len() {
        bail!(
            "record length {} does not match available bytes {}",
            record_length,
            data.len()
        );
    }

    let major_version = u16::from_le_bytes(data[4..6].try_into()?);
    let minor_version = u16::from_le_bytes(data[6..8].try_into()?);

    match major_version {
        2 => Ok(Some(parse_record_v2(
            data,
            record_offset,
            major_version,
            minor_version,
            path,
            metadata,
        )?)),
        3 => Ok(Some(parse_record_v3(
            data,
            record_offset,
            major_version,
            minor_version,
            path,
            metadata,
        )?)),
        _ => Ok(None),
    }
}

fn parse_record_v2(
    data: &[u8],
    record_offset: u64,
    major_version: u16,
    minor_version: u16,
    path: &Path,
    metadata: Option<&UsnMetadataSidecar>,
) -> Result<Map<String, Value>> {
    if data.len() < USN_RECORD_V2_HEADER_SIZE {
        bail!(
            "USN_RECORD_V2 shorter than {} bytes",
            USN_RECORD_V2_HEADER_SIZE
        );
    }

    let file_reference_number = format!("0x{:016X}", u64::from_le_bytes(data[8..16].try_into()?));
    let parent_file_reference_number =
        format!("0x{:016X}", u64::from_le_bytes(data[16..24].try_into()?));
    let usn = u64::from_le_bytes(data[24..32].try_into()?);
    let timestamp = u64::from_le_bytes(data[32..40].try_into()?);
    let reason = u32::from_le_bytes(data[40..44].try_into()?);
    let source_info = u32::from_le_bytes(data[44..48].try_into()?);
    let security_id = u32::from_le_bytes(data[48..52].try_into()?);
    let file_attributes = u32::from_le_bytes(data[52..56].try_into()?);
    let file_name_length = u16::from_le_bytes(data[56..58].try_into()?) as usize;
    let file_name_offset = u16::from_le_bytes(data[58..60].try_into()?) as usize;
    let file_name = decode_file_name(data, file_name_offset, file_name_length)?;

    build_record(
        record_offset,
        data.len() as u64,
        major_version,
        minor_version,
        &file_reference_number,
        &parent_file_reference_number,
        usn,
        timestamp,
        reason,
        source_info,
        security_id,
        file_attributes,
        file_name_length as u64,
        file_name_offset as u64,
        &file_name,
        path,
        metadata,
    )
}

fn parse_record_v3(
    data: &[u8],
    record_offset: u64,
    major_version: u16,
    minor_version: u16,
    path: &Path,
    metadata: Option<&UsnMetadataSidecar>,
) -> Result<Map<String, Value>> {
    if data.len() < USN_RECORD_V3_HEADER_SIZE {
        bail!(
            "USN_RECORD_V3 shorter than {} bytes",
            USN_RECORD_V3_HEADER_SIZE
        );
    }

    let file_reference_number = format!("0x{:032X}", u128::from_le_bytes(data[8..24].try_into()?));
    let parent_file_reference_number =
        format!("0x{:032X}", u128::from_le_bytes(data[24..40].try_into()?));
    let usn = u64::from_le_bytes(data[40..48].try_into()?);
    let timestamp = u64::from_le_bytes(data[48..56].try_into()?);
    let reason = u32::from_le_bytes(data[56..60].try_into()?);
    let source_info = u32::from_le_bytes(data[60..64].try_into()?);
    let security_id = u32::from_le_bytes(data[64..68].try_into()?);
    let file_attributes = u32::from_le_bytes(data[68..72].try_into()?);
    let file_name_length = u16::from_le_bytes(data[72..74].try_into()?) as usize;
    let file_name_offset = u16::from_le_bytes(data[74..76].try_into()?) as usize;
    let file_name = decode_file_name(data, file_name_offset, file_name_length)?;

    build_record(
        record_offset,
        data.len() as u64,
        major_version,
        minor_version,
        &file_reference_number,
        &parent_file_reference_number,
        usn,
        timestamp,
        reason,
        source_info,
        security_id,
        file_attributes,
        file_name_length as u64,
        file_name_offset as u64,
        &file_name,
        path,
        metadata,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    record_offset: u64,
    record_length: u64,
    major_version: u16,
    minor_version: u16,
    file_reference_number: &str,
    parent_file_reference_number: &str,
    usn: u64,
    timestamp: u64,
    reason: u32,
    source_info: u32,
    security_id: u32,
    file_attributes: u32,
    file_name_length: u64,
    file_name_offset: u64,
    file_name: &str,
    path: &Path,
    metadata: Option<&UsnMetadataSidecar>,
) -> Result<Map<String, Value>> {
    let mut record = Map::new();
    record.insert(
        "data_type".to_string(),
        Value::String("windows:filesystem:usn_journal_record".to_string()),
    );
    record.insert("record_offset".to_string(), Value::from(record_offset));
    record.insert("record_length".to_string(), Value::from(record_length));
    record.insert("major_version".to_string(), Value::from(major_version));
    record.insert("minor_version".to_string(), Value::from(minor_version));
    record.insert(
        "file_reference_number".to_string(),
        Value::String(file_reference_number.to_string()),
    );
    record.insert(
        "parent_file_reference_number".to_string(),
        Value::String(parent_file_reference_number.to_string()),
    );
    record.insert("usn".to_string(), Value::from(usn));
    record.insert("timestamp_filetime".to_string(), Value::from(timestamp));
    record.insert("reason".to_string(), Value::from(reason));
    record.insert("source_info".to_string(), Value::from(source_info));
    record.insert("security_id".to_string(), Value::from(security_id));
    record.insert("file_attributes".to_string(), Value::from(file_attributes));
    record.insert(
        "file_name".to_string(),
        Value::String(file_name.to_string()),
    );
    record.insert(
        "file_name_length".to_string(),
        Value::from(file_name_length),
    );
    record.insert(
        "file_name_offset".to_string(),
        Value::from(file_name_offset),
    );
    record.insert(
        "os_path".to_string(),
        Value::String(path.display().to_string()),
    );

    if let Some(value) = filetime_to_rfc3339(timestamp) {
        record.insert("timestamp".to_string(), Value::String(value));
    }
    if let Some(metadata) = metadata {
        if !metadata.volume.is_empty() {
            record.insert("volume".to_string(), Value::String(metadata.volume.clone()));
        }
        if !metadata.source_access_method.is_empty() {
            record.insert(
                "source_access_method".to_string(),
                Value::String(metadata.source_access_method.clone()),
            );
        }
    }

    insert_string_array(&mut record, "reason_flags", reason_flags(reason));
    insert_string_array(&mut record, "source_flags", source_flags(source_info));
    insert_string_array(
        &mut record,
        "file_attribute_flags",
        file_attribute_flags(file_attributes),
    );

    Ok(record)
}

fn load_sidecar(root: &Path, path: &Path) -> Result<Option<UsnMetadataSidecar>> {
    for metadata_path in metadata_candidate_paths(root, path)? {
        if !metadata_path.exists() {
            continue;
        }

        let data = fs::read(&metadata_path)
            .with_context(|| format!("read USN metadata {}", metadata_path.display()))?;
        let metadata = serde_json::from_slice::<UsnMetadataSidecar>(&data)
            .with_context(|| format!("parse USN metadata {}", metadata_path.display()))?;
        return Ok(Some(metadata));
    }
    Ok(None)
}

fn metadata_candidate_paths(root: &Path, path: &Path) -> Result<Vec<PathBuf>> {
    let mut candidates = vec![metadata_sidecar_path(path)];
    if let Some(volume) = archive_volume_for_usn_path(root, path) {
        candidates.push(
            root.join(collection_metadata::collector_manifest_archive_path(
                &volume,
                collection_metadata::WINDOWS_USN_JOURNAL_COLLECTOR,
            )?),
        );
    }
    Ok(candidates)
}

fn metadata_sidecar_path(path: &Path) -> PathBuf {
    path.with_extension("bin.metadata.json")
}

fn archive_volume_for_usn_path(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    if is_structured_usn_journal_artifact(path) {
        return relative
            .components()
            .next()
            .and_then(|component| component.as_os_str().to_str())
            .map(str::to_string);
    }

    let file_name = relative.file_name()?.to_str()?.to_ascii_lowercase();
    let volume = file_name.strip_suffix(USN_ARTIFACT_SUFFIX)?;
    (!volume.is_empty()).then(|| volume.to_ascii_uppercase())
}

fn parse_window(metadata: Option<&UsnMetadataSidecar>, file_len: u64) -> (u64, u64) {
    let default_window = (0, file_len);
    let Some(metadata) = metadata else {
        return default_window;
    };
    let Some(journal_data) = metadata.usn_journal_data.as_ref() else {
        return default_window;
    };

    let start = parse_u64_field(&journal_data.first_usn)
        .and_then(|value| value.checked_sub(metadata.output_logical_base))
        .unwrap_or(0);
    let end = parse_u64_field(&journal_data.next_usn)
        .and_then(|value| value.checked_sub(metadata.output_logical_base))
        .unwrap_or(file_len)
        .min(file_len);
    if start >= end {
        default_window
    } else {
        (start, end)
    }
}

fn build_ranges(
    metadata: Option<&UsnMetadataSidecar>,
    parse_start: u64,
    parse_end: u64,
) -> Vec<LogicalRange> {
    if parse_start >= parse_end {
        return Vec::new();
    }

    let Some(metadata) = metadata else {
        return vec![LogicalRange {
            start: parse_start,
            length: parse_end - parse_start,
        }];
    };

    if metadata.data_runs.is_empty() {
        return vec![LogicalRange {
            start: parse_start,
            length: parse_end - parse_start,
        }];
    }

    let mut ranges: Vec<LogicalRange> = Vec::new();
    for run in metadata
        .data_runs
        .iter()
        .filter(|run| !run.sparse && run.length > 0)
    {
        let run_start = run.logical_offset.max(parse_start);
        let run_end = run.logical_offset.saturating_add(run.length).min(parse_end);
        if run_start >= run_end {
            continue;
        }

        let next = LogicalRange {
            start: run_start,
            length: run_end - run_start,
        };
        if let Some(previous) = ranges.last_mut()
            && previous.start + previous.length == next.start
        {
            previous.length += next.length;
            continue;
        }

        ranges.push(next);
    }

    if ranges.is_empty() {
        vec![LogicalRange {
            start: parse_start,
            length: parse_end - parse_start,
        }]
    } else {
        ranges
    }
}

fn parse_u64_field(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse().ok()
    }
}

fn decode_file_name(
    data: &[u8],
    file_name_offset: usize,
    file_name_length: usize,
) -> Result<String> {
    let file_name_end = file_name_offset
        .checked_add(file_name_length)
        .ok_or_else(|| anyhow!("file name bounds overflow"))?;
    if file_name_offset >= data.len() || file_name_end > data.len() {
        bail!(
            "file name bounds {}..{} exceed record size {}",
            file_name_offset,
            file_name_end,
            data.len()
        );
    }

    Ok(decode_utf16_record(&data[file_name_offset..file_name_end]))
}

fn is_usn_journal_artifact(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase().ends_with(USN_ARTIFACT_SUFFIX))
        .unwrap_or(false)
        || is_structured_usn_journal_artifact(path)
}

fn is_structured_usn_journal_artifact(path: &Path) -> bool {
    file_name_equals(path, USN_ARCHIVE_STREAM_FILE)
        && path
            .parent()
            .map(|parent| file_name_equals(parent, USN_ARCHIVE_STREAM_PARENT))
            .unwrap_or(false)
        && path
            .parent()
            .and_then(Path::parent)
            .map(|grandparent| file_name_equals(grandparent, USN_ARCHIVE_STREAM_GRANDPARENT))
            .unwrap_or(false)
}

fn insert_string_array(record: &mut Map<String, Value>, key: &str, values: Vec<&'static str>) {
    if values.is_empty() {
        return;
    }

    record.insert(
        key.to_string(),
        Value::Array(
            values
                .into_iter()
                .map(|value| Value::String(value.to_string()))
                .collect(),
        ),
    );
}

fn reason_flags(reason: u32) -> Vec<&'static str> {
    collect_flags(
        reason,
        &[
            (0x0000_0001, "DATA_OVERWRITE"),
            (0x0000_0002, "DATA_EXTEND"),
            (0x0000_0004, "DATA_TRUNCATION"),
            (0x0000_0010, "NAMED_DATA_OVERWRITE"),
            (0x0000_0020, "NAMED_DATA_EXTEND"),
            (0x0000_0040, "NAMED_DATA_TRUNCATION"),
            (0x0000_0100, "FILE_CREATE"),
            (0x0000_0200, "FILE_DELETE"),
            (0x0000_0400, "EA_CHANGE"),
            (0x0000_0800, "SECURITY_CHANGE"),
            (0x0000_1000, "RENAME_OLD_NAME"),
            (0x0000_2000, "RENAME_NEW_NAME"),
            (0x0000_4000, "INDEXABLE_CHANGE"),
            (0x0000_8000, "BASIC_INFO_CHANGE"),
            (0x0001_0000, "HARD_LINK_CHANGE"),
            (0x0002_0000, "COMPRESSION_CHANGE"),
            (0x0004_0000, "ENCRYPTION_CHANGE"),
            (0x0008_0000, "OBJECT_ID_CHANGE"),
            (0x0010_0000, "REPARSE_POINT_CHANGE"),
            (0x0020_0000, "STREAM_CHANGE"),
            (0x0040_0000, "TRANSACTED_CHANGE"),
            (0x0080_0000, "INTEGRITY_CHANGE"),
            (0x8000_0000, "CLOSE"),
        ],
    )
}

fn source_flags(source_info: u32) -> Vec<&'static str> {
    collect_flags(
        source_info,
        &[
            (0x0000_0001, "DATA_MANAGEMENT"),
            (0x0000_0002, "AUXILIARY_DATA"),
            (0x0000_0004, "REPLICATION_MANAGEMENT"),
            (0x0000_0008, "CLIENT_REPLICATION_MANAGEMENT"),
        ],
    )
}

fn file_attribute_flags(file_attributes: u32) -> Vec<&'static str> {
    collect_flags(
        file_attributes,
        &[
            (0x0000_0001, "READONLY"),
            (0x0000_0002, "HIDDEN"),
            (0x0000_0004, "SYSTEM"),
            (0x0000_0010, "DIRECTORY"),
            (0x0000_0020, "ARCHIVE"),
            (0x0000_0080, "NORMAL"),
            (0x0000_0100, "TEMPORARY"),
            (0x0000_0200, "SPARSE_FILE"),
            (0x0000_0400, "REPARSE_POINT"),
            (0x0000_0800, "COMPRESSED"),
            (0x0000_1000, "OFFLINE"),
            (0x0000_2000, "NOT_CONTENT_INDEXED"),
            (0x0000_4000, "ENCRYPTED"),
            (0x0000_8000, "INTEGRITY_STREAM"),
        ],
    )
}

fn collect_flags(value: u32, flags: &[(u32, &'static str)]) -> Vec<&'static str> {
    flags
        .iter()
        .filter_map(|(mask, name)| ((value & mask) != 0).then_some(*name))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use anyhow::Result;
    use serde_json::Value;
    use tempfile::tempdir;

    use super::{
        LogicalRange, ParserFamily, UsnDataRun, UsnMetadataSidecar, build, build_ranges, collect,
        parse_record,
    };
    use crate::collection_metadata;
    use crate::parsers::common::required_root;

    #[test]
    fn build_returns_plan_for_usn_sample_name() -> Result<()> {
        let temp = tempdir()?;
        fs::write(temp.path().join("C_usn_journal_J.bin"), [])?;
        let family = ParserFamily {
            name: "windows_usn_journal".to_string(),
            collection: "windows_usn_journal_collection".to_string(),
            enabled: true,
            args: Default::default(),
            per_artifact_args: Default::default(),
        };

        let plans = build(temp.path(), &family)?;
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].artifact, "Windows.NTFS.UsnJournal.RawStream");
        assert_eq!(required_root(&plans[0])?, temp.path());
        Ok(())
    }

    #[test]
    fn build_returns_plan_for_structured_usn_archive_path() -> Result<()> {
        let temp = tempdir()?;
        let input_path = temp
            .path()
            .join("C")
            .join("$Extend")
            .join("$UsnJrnl")
            .join("$J.bin");
        fs::create_dir_all(input_path.parent().expect("archive path parent"))?;
        fs::write(&input_path, [])?;
        let family = ParserFamily {
            name: "windows_usn_journal".to_string(),
            collection: "windows_usn_journal_collection".to_string(),
            enabled: true,
            args: Default::default(),
            per_artifact_args: Default::default(),
        };

        let plans = build(temp.path(), &family)?;
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].artifact, "Windows.NTFS.UsnJournal.RawStream");
        assert_eq!(required_root(&plans[0])?, temp.path());
        Ok(())
    }

    #[test]
    fn build_ranges_merges_adjacent_non_sparse_runs() {
        let metadata = UsnMetadataSidecar {
            volume: String::new(),
            source_access_method: String::new(),
            output_logical_base: 0,
            usn_journal_data: None,
            data_runs: vec![
                UsnDataRun {
                    logical_offset: 0,
                    length: 128,
                    sparse: true,
                },
                UsnDataRun {
                    logical_offset: 128,
                    length: 64,
                    sparse: false,
                },
                UsnDataRun {
                    logical_offset: 192,
                    length: 32,
                    sparse: false,
                },
            ],
        };

        let ranges = build_ranges(Some(&metadata), 128, 224);
        assert_eq!(
            ranges,
            vec![LogicalRange {
                start: 128,
                length: 96
            }]
        );
    }

    #[test]
    fn parse_record_v3_formats_128bit_references() -> Result<()> {
        let record = build_v3_record("hello.txt", 99, 0x0000_0100, 0x0000_0010)?;
        let parsed = parse_record(&record, 8192, Path::new("C_usn_journal_J.bin"), None)?
            .expect("record should parse");

        assert_eq!(parsed.get("major_version"), Some(&Value::from(3)));
        assert_eq!(parsed.get("file_name"), Some(&Value::from("hello.txt")));
        assert_eq!(parsed.get("usn"), Some(&Value::from(99u64)));
        assert_eq!(
            parsed.get("file_reference_number"),
            Some(&Value::from("0x0102030405060708090A0B0C0D0E0F10"))
        );
        Ok(())
    }

    #[test]
    fn collect_uses_metadata_window_and_emits_v2_records() -> Result<()> {
        let temp = tempdir()?;
        let root = temp.path();
        let input_path = root.join("C_usn_journal_J.bin");
        let output_dir = root.join("results");
        let family = ParserFamily {
            name: "windows_usn_journal".to_string(),
            collection: "windows_usn_journal_collection".to_string(),
            enabled: true,
            args: Default::default(),
            per_artifact_args: Default::default(),
        };

        let offset = 4096usize;
        let record = build_v2_record("example.txt", 42, 0x8000_0100, 0x0000_0010)?;
        let mut data = vec![0u8; offset];
        data.extend_from_slice(&record);
        fs::write(&input_path, data)?;

        let metadata = serde_json::json!({
            "volume": "C:",
            "source_access_method": "vss_raw_ntfs",
            "usn_journal_data": {
                "first_usn": offset.to_string(),
                "next_usn": (offset + record.len()).to_string()
            },
            "data_runs": [
                { "logical_offset": 0, "length": offset, "sparse": true },
                { "logical_offset": offset, "length": record.len(), "sparse": false }
            ]
        });
        fs::write(
            input_path.with_extension("bin.metadata.json"),
            serde_json::to_vec_pretty(&metadata)?,
        )?;

        let plan = build(root, &family)?.remove(0);

        let (output_path, log_path) = collect(&plan, &output_dir)?;
        let output = fs::read_to_string(output_path)?;
        let log = fs::read_to_string(log_path)?;

        let mut lines = output.lines();
        let parsed: Value = serde_json::from_str(lines.next().expect("one output record"))?;
        assert!(lines.next().is_none());
        assert_eq!(parsed.get("file_name"), Some(&Value::from("example.txt")));
        assert_eq!(parsed.get("volume"), Some(&Value::from("C:")));
        assert_eq!(
            parsed.get("source_access_method"),
            Some(&Value::from("vss_raw_ntfs"))
        );
        assert_eq!(
            parsed.get("record_offset"),
            Some(&Value::from(offset as u64))
        );
        assert_eq!(
            parsed
                .get("reason_flags")
                .and_then(Value::as_array)
                .map(|values| values.len()),
            Some(2)
        );
        assert!(log.contains("files=1 records=1"));
        Ok(())
    }

    #[test]
    fn collect_supports_structured_archive_layout() -> Result<()> {
        let temp = tempdir()?;
        let root = temp.path();
        let input_path = root
            .join("C")
            .join("$Extend")
            .join("$UsnJrnl")
            .join("$J.bin");
        let output_dir = root.join("results");
        let family = ParserFamily {
            name: "windows_usn_journal".to_string(),
            collection: "windows_usn_journal_collection".to_string(),
            enabled: true,
            args: Default::default(),
            per_artifact_args: Default::default(),
        };

        fs::create_dir_all(input_path.parent().expect("archive path parent"))?;

        let record = build_v2_record("example.txt", 42, 0x8000_0100, 0x0000_0010)?;
        fs::write(&input_path, &record)?;
        let metadata_path = root.join(collection_metadata::collector_manifest_archive_path(
            "C:",
            collection_metadata::WINDOWS_USN_JOURNAL_COLLECTOR,
        )?);
        fs::create_dir_all(metadata_path.parent().expect("metadata parent"))?;
        fs::write(
            metadata_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "volume": "C:",
                "source_access_method": "zip_archive",
                "usn_journal_data": {
                    "first_usn": "0",
                    "next_usn": record.len().to_string()
                }
            }))?,
        )?;

        let plan = build(root, &family)?.remove(0);
        let (output_path, log_path) = collect(&plan, &output_dir)?;
        let output = fs::read_to_string(output_path)?;
        let log = fs::read_to_string(log_path)?;

        let parsed: Value =
            serde_json::from_str(output.lines().next().expect("one output record"))?;
        assert_eq!(parsed.get("file_name"), Some(&Value::from("example.txt")));
        assert_eq!(parsed.get("volume"), Some(&Value::from("C:")));
        assert_eq!(
            parsed.get("source_access_method"),
            Some(&Value::from("zip_archive"))
        );
        assert!(log.contains("files=1 records=1"));
        Ok(())
    }

    #[test]
    fn collect_suppresses_trailing_zero_padding_noise() -> Result<()> {
        let temp = tempdir()?;
        let root = temp.path();
        let input_path = root.join("C_usn_journal_J.bin");
        let output_dir = root.join("results");
        let family = ParserFamily {
            name: "windows_usn_journal".to_string(),
            collection: "windows_usn_journal_collection".to_string(),
            enabled: true,
            args: Default::default(),
            per_artifact_args: Default::default(),
        };

        let record = build_v2_record("example.txt", 42, 0x8000_0100, 0x0000_0010)?;
        let mut data = record.clone();
        data.extend_from_slice(&[0u8; 128]);
        fs::write(&input_path, data)?;
        fs::write(
            input_path.with_extension("bin.metadata.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "volume": "C:",
                "source_access_method": "zip_fixture_active_window",
                "usn_journal_data": {
                    "first_usn": "0",
                    "next_usn": (record.len() + 128).to_string()
                },
                "data_runs": [
                    { "logical_offset": 0, "length": record.len() + 128, "sparse": false }
                ]
            }))?,
        )?;

        let plan = build(root, &family)?.remove(0);
        let (_output_path, log_path) = collect(&plan, &output_dir)?;
        let log = fs::read_to_string(log_path)?;

        assert!(!log.contains("zero-length record at offset"));
        assert!(log.contains("files=1 records=1"));
        Ok(())
    }

    #[test]
    fn collect_applies_output_logical_base_to_record_offsets() -> Result<()> {
        let temp = tempdir()?;
        let root = temp.path();
        let input_path = root.join("C_usn_journal_J.bin");
        let output_dir = root.join("results");
        let family = ParserFamily {
            name: "windows_usn_journal".to_string(),
            collection: "windows_usn_journal_collection".to_string(),
            enabled: true,
            args: Default::default(),
            per_artifact_args: Default::default(),
        };

        let record = build_v2_record("example.txt", 42, 0x8000_0100, 0x0000_0010)?;
        fs::write(&input_path, &record)?;
        fs::write(
            input_path.with_extension("bin.metadata.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "volume": "C:",
                "source_access_method": "vss_raw_ntfs",
                "output_logical_base": 4096,
                "usn_journal_data": {
                    "first_usn": "4096",
                    "next_usn": (4096 + record.len()).to_string()
                }
            }))?,
        )?;

        let plan = build(root, &family)?.remove(0);
        let (output_path, _log_path) = collect(&plan, &output_dir)?;
        let output = fs::read_to_string(output_path)?;

        let parsed: Value =
            serde_json::from_str(output.lines().next().expect("one output record"))?;
        assert_eq!(parsed.get("record_offset"), Some(&Value::from(4096u64)));
        Ok(())
    }

    fn build_v2_record(
        file_name: &str,
        usn: u64,
        reason: u32,
        file_attributes: u32,
    ) -> Result<Vec<u8>> {
        let file_name_utf16 = encode_utf16(file_name);
        let file_name_offset = 60u16;
        let file_name_length = file_name_utf16.len() as u16;
        let record_length = align_to_eight(file_name_offset as usize + file_name_utf16.len());
        let mut data = vec![0u8; record_length];

        data[0..4].copy_from_slice(&(record_length as u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        data[6..8].copy_from_slice(&0u16.to_le_bytes());
        data[8..16].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        data[16..24].copy_from_slice(&0x1112_1314_1516_1718u64.to_le_bytes());
        data[24..32].copy_from_slice(&usn.to_le_bytes());
        data[32..40].copy_from_slice(&132_537_600_000_000_000u64.to_le_bytes());
        data[40..44].copy_from_slice(&reason.to_le_bytes());
        data[44..48].copy_from_slice(&0u32.to_le_bytes());
        data[48..52].copy_from_slice(&77u32.to_le_bytes());
        data[52..56].copy_from_slice(&file_attributes.to_le_bytes());
        data[56..58].copy_from_slice(&file_name_length.to_le_bytes());
        data[58..60].copy_from_slice(&file_name_offset.to_le_bytes());
        data[file_name_offset as usize..file_name_offset as usize + file_name_utf16.len()]
            .copy_from_slice(&file_name_utf16);

        Ok(data)
    }

    fn build_v3_record(
        file_name: &str,
        usn: u64,
        reason: u32,
        file_attributes: u32,
    ) -> Result<Vec<u8>> {
        let file_name_utf16 = encode_utf16(file_name);
        let file_name_offset = 76u16;
        let file_name_length = file_name_utf16.len() as u16;
        let record_length = align_to_eight(file_name_offset as usize + file_name_utf16.len());
        let mut data = vec![0u8; record_length];

        data[0..4].copy_from_slice(&(record_length as u32).to_le_bytes());
        data[4..6].copy_from_slice(&3u16.to_le_bytes());
        data[6..8].copy_from_slice(&0u16.to_le_bytes());
        data[8..24].copy_from_slice(
            &u128::from_be_bytes([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ])
            .to_le_bytes(),
        );
        data[24..40].copy_from_slice(
            &u128::from_be_bytes([
                0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
                0x02, 0x01,
            ])
            .to_le_bytes(),
        );
        data[40..48].copy_from_slice(&usn.to_le_bytes());
        data[48..56].copy_from_slice(&132_537_600_000_000_000u64.to_le_bytes());
        data[56..60].copy_from_slice(&reason.to_le_bytes());
        data[60..64].copy_from_slice(&0u32.to_le_bytes());
        data[64..68].copy_from_slice(&88u32.to_le_bytes());
        data[68..72].copy_from_slice(&file_attributes.to_le_bytes());
        data[72..74].copy_from_slice(&file_name_length.to_le_bytes());
        data[74..76].copy_from_slice(&file_name_offset.to_le_bytes());
        data[file_name_offset as usize..file_name_offset as usize + file_name_utf16.len()]
            .copy_from_slice(&file_name_utf16);

        Ok(data)
    }

    fn align_to_eight(value: usize) -> usize {
        (value + 7) & !7
    }

    fn encode_utf16(value: &str) -> Vec<u8> {
        value
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    }
}
