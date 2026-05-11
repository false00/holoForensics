use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use notatin::cell_key_node::CellKeyNode;
use notatin::cell_key_value::CellKeyValue;
use notatin::parser::ParserIterator;
use notatin::parser_builder::ParserBuilder;
use rayon::prelude::*;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::parser_catalog::ParserFamily;
use crate::parsers::common::{
    Plan, create_output_files, find_paths, new_local_plan, required_root, sanitize_name,
    windows_user_from_path,
};

const DELETED_RECOVERY_ENABLED: bool = false;
const PARSER_NAME: &str = "notatin";
const PARSER_VERSION: &str = "1.0.1";
const PARSER_SCHEMA: &str = "windows_registry_key_v1";

pub fn build(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    let paths = find_registry_hives(root)?;
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![new_local_plan(
        family,
        root,
        "Windows.Registry.Hive",
        "windows.registry.hive",
    )])
}

pub fn collect(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let root = required_root(plan)?;
    let paths = find_registry_hives(&root)?;
    let parts_dir = output_dir.join(format!(".{}-parts", plan.output_name));
    if parts_dir.exists() {
        fs::remove_dir_all(&parts_dir)
            .with_context(|| format!("remove temp directory {}", parts_dir.display()))?;
    }
    fs::create_dir_all(&parts_dir)
        .with_context(|| format!("create temp directory {}", parts_dir.display()))?;

    let part_results = paths
        .par_iter()
        .enumerate()
        .map(|(index, path)| {
            collect_hive_to_part(path, &parts_dir, index).map_err(|error| HivePartError {
                path: path.clone(),
                error,
            })
        })
        .collect::<Vec<_>>();

    let (mut output_file, mut log_file, output_path, log_path) =
        create_output_files(output_dir, &plan.output_name)?;

    let mut hive_count = 0usize;
    let mut key_count = 0usize;

    for part_result in part_results {
        match part_result {
            Ok(part) => {
                hive_count += 1;
                key_count += part.records;
                append_file_contents(&part.output_path, &mut output_file)?;
                append_file_contents(&part.log_path, &mut log_file)?;
                fs::remove_file(&part.output_path).with_context(|| {
                    format!("remove temp output {}", part.output_path.display())
                })?;
                fs::remove_file(&part.log_path)
                    .with_context(|| format!("remove temp log {}", part.log_path.display()))?;
            }
            Err(error) => writeln!(log_file, "skip {}: {}", error.path.display(), error.error)?,
        }
    }

    fs::remove_dir_all(&parts_dir)
        .with_context(|| format!("remove temp directory {}", parts_dir.display()))?;

    writeln!(log_file, "hives={hive_count} keys={key_count}")?;
    Ok((output_path, log_path))
}

fn is_registry_hive(path: &Path) -> bool {
    if is_transaction_log(path) || !is_registry_hive_candidate(path) {
        return false;
    }

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut magic = [0u8; 4];
    matches!(file.read_exact(&mut magic), Ok(())) && magic == *b"regf"
}

fn find_registry_hives(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = find_paths(root, is_registry_hive)?;
    paths.sort_by_key(|path| path.display().to_string().to_ascii_lowercase());
    Ok(paths)
}

fn is_registry_hive_candidate(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "ntuser.dat"
                    | "usrclass.dat"
                    | "amcache.hve"
                    | "sam"
                    | "security"
                    | "software"
                    | "system"
                    | "default"
                    | "components"
                    | "settings.dat"
                    | "drvindex.dat"
            )
        })
        .unwrap_or(false)
}

fn is_transaction_log(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.ends_with(".log1") || value.ends_with(".log2")
        })
        .unwrap_or(false)
}

fn collect_hive_to_part(path: &Path, parts_dir: &Path, index: usize) -> Result<HivePart> {
    let part_base_name = format!(
        "{index:03}-{}",
        sanitize_name(
            path.file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("registry")
        )
    );
    let output_path = parts_dir.join(format!("{part_base_name}.jsonl"));
    let log_path = parts_dir.join(format!("{part_base_name}.log"));
    let output_file = File::create(&output_path)
        .with_context(|| format!("create temp output {}", output_path.display()))?;
    let log_file = File::create(&log_path)
        .with_context(|| format!("create temp log {}", log_path.display()))?;
    let mut output_writer = BufWriter::new(output_file);
    let mut log_writer = BufWriter::new(log_file);

    let transaction_logs = discover_transaction_logs(path)?;
    #[allow(clippy::unnecessary_to_owned)]
    let mut builder = ParserBuilder::from_path(path.to_path_buf());
    builder.recover_deleted(DELETED_RECOVERY_ENABLED);
    for log_path in &transaction_logs {
        builder.with_transaction_log(log_path.clone());
    }

    let parser = builder
        .build()
        .with_context(|| format!("parse registry hive {}", path.display()))?;

    let transaction_logs_found = !transaction_logs.is_empty();
    let transaction_logs_applied = parser
        .get_parse_logs()
        .get()
        .map(|logs| {
            logs.iter()
                .any(|log| log.text.contains("Applied transaction log(s)."))
        })
        .unwrap_or(false);

    if parser.get_parse_logs().has_logs() {
        writeln!(
            log_writer,
            "{}: {}",
            path.display(),
            parser.get_parse_logs()
        )?;
    }

    let hive_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string();
    let hive_role = hive_role(&hive_name);
    let user = windows_user_from_path(path);
    let source_path = path.display().to_string();
    let hive_user_context = hive_user_context_from_source_path(&source_path);
    let transaction_log_values = transaction_logs
        .iter()
        .map(|log_path| log_path.display().to_string())
        .collect::<Vec<_>>();
    let parser_metadata = parser_metadata(Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true));

    let mut records = 0usize;
    for key in ParserIterator::new(&parser).iter() {
        let record = build_key_record(
            &key,
            &hive_name,
            hive_role,
            &user,
            hive_user_context.as_deref(),
            &source_path,
            &transaction_log_values,
            transaction_logs_found,
            transaction_logs_applied,
            DELETED_RECOVERY_ENABLED,
            &parser_metadata,
        )?;
        write_json_line_buffered(&mut output_writer, &record)?;
        records += 1;
    }

    writeln!(
        log_writer,
        "parsed {} keys from {}",
        records,
        path.display()
    )?;
    output_writer.flush()?;
    log_writer.flush()?;

    Ok(HivePart {
        output_path,
        log_path,
        records,
    })
}

fn discover_transaction_logs(path: &Path) -> Result<Vec<PathBuf>> {
    let Some(parent) = path.parent() else {
        return Ok(Vec::new());
    };
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Ok(Vec::new());
    };

    let base_name = file_name.to_ascii_lowercase();
    let expected = [format!("{base_name}.log1"), format!("{base_name}.log2")];
    let mut logs = fs::read_dir(parent)
        .with_context(|| format!("read directory {}", parent.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|candidate| {
            candidate
                .file_name()
                .and_then(|value| value.to_str())
                .map(|value| {
                    let value = value.to_ascii_lowercase();
                    expected.iter().any(|target| target == &value)
                })
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    logs.sort_by_key(|log_path| log_path.display().to_string().to_ascii_lowercase());
    Ok(logs)
}

fn hive_role(file_name: &str) -> &'static str {
    match file_name.to_ascii_lowercase().as_str() {
        "ntuser.dat" => "ntuser",
        "usrclass.dat" => "usrclass",
        "amcache.hve" => "amcache",
        "sam" => "sam",
        "security" => "security",
        "software" => "software",
        "system" => "system",
        "default" => "default",
        "components" => "components",
        "settings.dat" => "settings",
        "drvindex.dat" => "drvindex",
        _ => "registry",
    }
}

fn build_key_record(
    key: &CellKeyNode,
    hive_name: &str,
    hive_role: &str,
    user: &str,
    hive_user_context: Option<&str>,
    source_path: &str,
    transaction_logs: &[String],
    transaction_logs_found: bool,
    transaction_logs_applied: bool,
    deleted_recovery_enabled: bool,
    parser_metadata: &Value,
) -> Result<Value> {
    let values = key
        .value_iter()
        .map(|value| build_value_record(&value))
        .collect::<Result<Vec<_>>>()?;

    let registry_path_metadata = build_registry_path_metadata(hive_role, &key.path);
    let cell_state = format!("{:?}", key.cell_state);
    let is_recovered_deleted = key.cell_state.is_deleted();

    let mut record = Map::new();
    record.insert(
        "data_type".to_string(),
        Value::String("windows:registry:key".to_string()),
    );
    record.insert(
        "hive_name".to_string(),
        Value::String(hive_name.to_string()),
    );
    record.insert(
        "hive_role".to_string(),
        Value::String(hive_role.to_string()),
    );
    if !user.is_empty() {
        record.insert("user".to_string(), Value::String(user.to_string()));
    }
    if let Some(value) = hive_user_context {
        record.insert(
            "hive_user_context".to_string(),
            Value::String(value.to_string()),
        );
    }
    record.insert(
        "source_path".to_string(),
        Value::String(source_path.to_string()),
    );
    record.insert(
        "transaction_logs".to_string(),
        Value::Array(
            transaction_logs
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    record.insert(
        "transaction_logs_found".to_string(),
        Value::Bool(transaction_logs_found),
    );
    record.insert(
        "transaction_logs_applied".to_string(),
        Value::Bool(transaction_logs_applied),
    );
    record.insert(
        "deleted_recovery_enabled".to_string(),
        Value::Bool(deleted_recovery_enabled),
    );
    record.insert(
        "is_recovered_deleted".to_string(),
        Value::Bool(is_recovered_deleted),
    );
    record.insert("key_path".to_string(), Value::String(key.path.clone()));
    record.insert(
        "registry_path".to_string(),
        Value::String(registry_path_metadata.registry_path),
    );
    record.insert(
        "parent_key_path".to_string(),
        option_string_to_value(registry_path_metadata.parent_key_path),
    );
    record.insert("key_name".to_string(), Value::String(key.key_name.clone()));
    record.insert("cell_state".to_string(), Value::String(cell_state));
    record.insert(
        "file_offset_absolute".to_string(),
        Value::from(key.file_offset_absolute as u64),
    );
    record.insert(
        "last_write_time_utc".to_string(),
        Value::String(
            key.last_key_written_date_and_time()
                .to_rfc3339_opts(SecondsFormat::Nanos, true),
        ),
    );
    record.insert(
        "last_write_time_filetime".to_string(),
        Value::from(key.detail.last_key_written_date_and_time()),
    );
    record.insert(
        "subkey_count".to_string(),
        Value::from(key.detail.number_of_sub_keys()),
    );
    record.insert("value_count".to_string(), Value::from(values.len() as u64));

    let sub_keys_list_offset_relative_raw = key.detail.sub_keys_list_offset_relative();
    record.insert(
        "sub_keys_list_offset_relative".to_string(),
        option_u32_to_value(normalize_u32_sentinel(sub_keys_list_offset_relative_raw)),
    );
    record.insert(
        "sub_keys_list_offset_relative_raw".to_string(),
        Value::from(sub_keys_list_offset_relative_raw),
    );

    let key_values_list_offset_relative_raw = key.detail.key_values_list_offset_relative();
    record.insert(
        "key_values_list_offset_relative".to_string(),
        option_i32_to_value(normalize_i32_sentinel(key_values_list_offset_relative_raw)),
    );
    record.insert(
        "key_values_list_offset_relative_raw".to_string(),
        Value::from(key_values_list_offset_relative_raw),
    );

    record.insert(
        "hive_mapping".to_string(),
        option_string_to_value(registry_path_metadata.hive_mapping),
    );
    record.insert(
        "sid".to_string(),
        option_string_to_value(registry_path_metadata.sid),
    );
    record.insert("parser".to_string(), parser_metadata.clone());

    record.insert("values".to_string(), Value::Array(values));

    let mut raw = Map::new();
    raw.insert("key_detail".to_string(), serde_json::to_value(&key.detail)?);
    if key.logs.has_logs() {
        raw.insert("key_logs".to_string(), serde_json::to_value(&key.logs)?);
    }
    record.insert("raw".to_string(), Value::Object(raw));

    Ok(Value::Object(record))
}

fn build_value_record(value: &CellKeyValue) -> Result<Value> {
    let raw_bytes = value.detail.value_bytes().clone().unwrap_or_default();
    let data_size_raw = value.detail.data_size_raw();
    let data_size = normalize_data_size(data_size_raw);
    let resident_data = is_resident_data(data_size_raw);
    let value_is_empty = raw_bytes.is_empty() && data_size == 0;
    let (decoded_value, decode_warnings) = value.get_content();

    let mut record = Map::new();
    record.insert(
        "value_name".to_string(),
        Value::String(value.get_pretty_name()),
    );
    record.insert(
        "data_type".to_string(),
        Value::String(format!("{:?}", value.data_type)),
    );
    record.insert(
        "value_data_length".to_string(),
        Value::from(raw_bytes.len() as u64),
    );
    record.insert(
        "value_data_hex".to_string(),
        Value::String(bytes_to_hex(&raw_bytes)),
    );
    record.insert(
        "value_decoded".to_string(),
        normalize_decoded_value(serde_json::to_value(&decoded_value)?, value_is_empty),
    );
    record.insert("value_is_empty".to_string(), Value::Bool(value_is_empty));
    record.insert("data_size_raw".to_string(), Value::from(data_size_raw));
    record.insert("data_size".to_string(), Value::from(data_size));
    record.insert("resident_data".to_string(), Value::Bool(resident_data));
    record.insert(
        "cell_state".to_string(),
        Value::String(format!("{:?}", value.cell_state)),
    );
    record.insert(
        "file_offset_absolute".to_string(),
        Value::from(value.file_offset_absolute as u64),
    );
    record.insert(
        "data_offsets_absolute".to_string(),
        Value::Array(
            value
                .data_offsets_absolute
                .iter()
                .map(|offset| Value::from(*offset as u64))
                .collect(),
        ),
    );
    if let Some(warnings) = decode_warnings {
        record.insert(
            "value_parse_warnings".to_string(),
            serde_json::to_value(&warnings)?,
        );
    }
    if value.logs.has_logs() {
        record.insert(
            "cell_parse_logs".to_string(),
            serde_json::to_value(&value.logs)?,
        );
    }

    Ok(Value::Object(record))
}

fn normalize_u32_sentinel(value: u32) -> Option<u32> {
    if value == u32::MAX { None } else { Some(value) }
}

fn normalize_i32_sentinel(value: i32) -> Option<i32> {
    if value == -1 { None } else { Some(value) }
}

fn option_u32_to_value(value: Option<u32>) -> Value {
    value.map(Value::from).unwrap_or(Value::Null)
}

fn option_i32_to_value(value: Option<i32>) -> Value {
    value.map(Value::from).unwrap_or(Value::Null)
}

fn is_resident_data(data_size_raw: u32) -> bool {
    data_size_raw & 0x8000_0000 != 0
}

fn normalize_data_size(data_size_raw: u32) -> u32 {
    if is_resident_data(data_size_raw) {
        data_size_raw ^ 0x8000_0000
    } else {
        data_size_raw
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(nibble_to_hex(byte >> 4));
        hex.push(nibble_to_hex(byte & 0x0f));
    }
    hex
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!(),
    }
}

fn normalize_decoded_value(value: Value, value_is_empty: bool) -> Value {
    if value_is_empty {
        return Value::Null;
    }

    match value {
        Value::Object(object) if object.len() == 1 => object
            .into_iter()
            .next()
            .map(|(_, inner)| inner)
            .unwrap_or(Value::Null),
        Value::String(text) if text == "None" => Value::Null,
        other => other,
    }
}

fn build_registry_path_metadata(hive_role: &str, key_path: &str) -> RegistryPathMetadata {
    let segments = key_path
        .trim_start_matches('\\')
        .split('\\')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();

    let root_segment = segments.first().copied().unwrap_or_default();
    let remaining_segments = if segments.is_empty() {
        &[][..]
    } else {
        &segments[1..]
    };
    let sid = extract_sid(root_segment);
    let registry_root = registry_root_for_hive(hive_role, root_segment);

    RegistryPathMetadata {
        registry_path: join_registry_path(&registry_root, remaining_segments),
        parent_key_path: parent_key_path(key_path),
        hive_mapping: hive_mapping(hive_role, sid.as_deref()),
        sid,
    }
}

fn extract_sid(root_segment: &str) -> Option<String> {
    let candidate = root_segment
        .strip_suffix("_Classes")
        .unwrap_or(root_segment);
    if candidate.starts_with("S-1-") {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn registry_root_for_hive(hive_role: &str, root_segment: &str) -> String {
    match hive_role {
        "ntuser" => {
            if root_segment.eq_ignore_ascii_case("ROOT") || root_segment.is_empty() {
                "HKCU".to_string()
            } else {
                format!("HKU\\{root_segment}")
            }
        }
        "usrclass" => format!("HKU\\{root_segment}"),
        "software" => "HKLM\\SOFTWARE".to_string(),
        "system" => "HKLM\\SYSTEM".to_string(),
        "sam" => "HKLM\\SAM".to_string(),
        "security" => "HKLM\\SECURITY".to_string(),
        "default" => "HKU\\.DEFAULT".to_string(),
        "components" => "HKLM\\COMPONENTS".to_string(),
        "amcache" => "HKLM\\Amcache".to_string(),
        "settings" => format!("Settings\\{root_segment}"),
        "drvindex" => format!("DrvIndex\\{root_segment}"),
        _ => root_segment.to_string(),
    }
}

fn join_registry_path(root: &str, remaining_segments: &[&str]) -> String {
    if remaining_segments.is_empty() {
        root.to_string()
    } else {
        format!("{root}\\{}", remaining_segments.join("\\"))
    }
}

fn parent_key_path(key_path: &str) -> Option<String> {
    let trimmed = key_path.trim_end_matches('\\');
    let separator_index = trimmed.rfind('\\')?;
    if separator_index == 0 {
        None
    } else {
        Some(trimmed[..separator_index].to_string())
    }
}

fn hive_mapping(hive_role: &str, sid: Option<&str>) -> Option<String> {
    match hive_role {
        "ntuser" => Some(
            sid.map(|_| "HKU\\<SID>".to_string())
                .unwrap_or_else(|| "HKCU".to_string()),
        ),
        "usrclass" => sid.map(|_| "HKU\\<SID>_Classes".to_string()),
        "software" => Some("HKLM\\SOFTWARE".to_string()),
        "system" => Some("HKLM\\SYSTEM".to_string()),
        "sam" => Some("HKLM\\SAM".to_string()),
        "security" => Some("HKLM\\SECURITY".to_string()),
        "default" => Some("HKU\\.DEFAULT".to_string()),
        "components" => Some("HKLM\\COMPONENTS".to_string()),
        "amcache" => Some("HKLM\\Amcache".to_string()),
        "settings" => Some("Settings".to_string()),
        "drvindex" => Some("DrvIndex".to_string()),
        _ => None,
    }
}

fn parser_metadata(timestamp_utc: String) -> Value {
    let mut metadata = Map::new();
    metadata.insert("name".to_string(), Value::String(PARSER_NAME.to_string()));
    metadata.insert(
        "version".to_string(),
        Value::String(PARSER_VERSION.to_string()),
    );
    metadata.insert(
        "schema".to_string(),
        Value::String(PARSER_SCHEMA.to_string()),
    );
    metadata.insert("timestamp_utc".to_string(), Value::String(timestamp_utc));
    Value::Object(metadata)
}

fn hive_user_context_from_source_path(source_path: &str) -> Option<String> {
    let normalized = source_path.replace('/', "\\");
    let parts = normalized.split('\\').collect::<Vec<_>>();
    for index in 0..parts.len().saturating_sub(1) {
        if parts[index].eq_ignore_ascii_case("Users")
            || parts[index].eq_ignore_ascii_case("ServiceProfiles")
        {
            return Some(parts[index + 1].to_string());
        }
    }
    None
}

fn option_string_to_value(value: Option<String>) -> Value {
    value.map(Value::String).unwrap_or(Value::Null)
}

fn append_file_contents(source_path: &Path, destination: &mut File) -> Result<()> {
    let mut source = File::open(source_path)
        .with_context(|| format!("open temp file {}", source_path.display()))?;
    io::copy(&mut source, destination)
        .with_context(|| format!("append temp file {}", source_path.display()))?;
    Ok(())
}

fn write_json_line_buffered<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

struct HivePart {
    output_path: PathBuf,
    log_path: PathBuf,
    records: usize,
}

struct HivePartError {
    path: PathBuf,
    error: anyhow::Error,
}

struct RegistryPathMetadata {
    registry_path: String,
    parent_key_path: Option<String>,
    hive_mapping: Option<String>,
    sid: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{
        build, build_registry_path_metadata, bytes_to_hex, hive_mapping,
        hive_user_context_from_source_path, is_registry_hive, is_registry_hive_candidate,
        is_resident_data, normalize_data_size, normalize_i32_sentinel, normalize_u32_sentinel,
    };
    use crate::parser_catalog::ParserFamily;

    #[test]
    fn is_registry_hive_matches_regf_magic() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("NTUSER.DAT");
        fs::write(&path, b"regf\0\0\0\0").unwrap();

        assert!(is_registry_hive(&path));
    }

    #[test]
    fn is_registry_hive_rejects_non_hives() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("note.txt");
        fs::write(&path, b"regf").unwrap();

        assert!(!is_registry_hive(&path));
    }

    #[test]
    fn is_registry_hive_candidate_matches_supported_names() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("UsrClass.dat");

        assert!(is_registry_hive_candidate(&path));
    }

    #[test]
    fn build_creates_a_plan_for_detected_hives() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("SYSTEM"), b"regf\0\0\0\0").unwrap();
        let family = ParserFamily {
            name: "windows_registry".to_string(),
            enabled: true,
            ..ParserFamily::default()
        };

        let plans = build(temp.path(), &family).unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].artifact, "Windows.Registry.Hive");
        assert_eq!(
            plans[0].local_collector.as_deref(),
            Some("windows.registry.hive")
        );
    }

    #[test]
    fn build_ignores_transaction_logs_as_hives() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("NTUSER.DAT.LOG1"), b"regf\0\0\0\0").unwrap();
        let family = ParserFamily {
            name: "windows_registry".to_string(),
            enabled: true,
            ..ParserFamily::default()
        };

        let plans = build(temp.path(), &family).unwrap();

        assert!(plans.is_empty());
    }

    #[test]
    fn normalize_offset_sentinels_to_none() {
        assert_eq!(normalize_u32_sentinel(u32::MAX), None);
        assert_eq!(normalize_u32_sentinel(4096), Some(4096));
        assert_eq!(normalize_i32_sentinel(-1), None);
        assert_eq!(normalize_i32_sentinel(128), Some(128));
    }

    #[test]
    fn normalize_data_size_handles_resident_values() {
        assert!(is_resident_data(0x8000_0000));
        assert_eq!(normalize_data_size(0x8000_0000), 0);
        assert_eq!(normalize_data_size(0x8000_0004), 4);
        assert_eq!(normalize_data_size(12), 12);
    }

    #[test]
    fn bytes_to_hex_returns_lowercase_hex() {
        assert_eq!(bytes_to_hex(&[0x00, 0xab, 0xcd, 0xef]), "00abcdef");
    }

    #[test]
    fn build_registry_path_metadata_maps_usrclass_keys() {
        let metadata = build_registry_path_metadata(
            "usrclass",
            r"\S-1-12-1-603450812-1318379816-386548866-3354084363_Classes\.3g2\OpenWithProgids",
        );

        assert_eq!(
            metadata.registry_path,
            r"HKU\S-1-12-1-603450812-1318379816-386548866-3354084363_Classes\.3g2\OpenWithProgids"
        );
        assert_eq!(
            metadata.parent_key_path,
            Some(r"\S-1-12-1-603450812-1318379816-386548866-3354084363_Classes\.3g2".to_string())
        );
        assert_eq!(
            metadata.sid,
            Some("S-1-12-1-603450812-1318379816-386548866-3354084363".to_string())
        );
        assert_eq!(
            metadata.hive_mapping,
            Some("HKU\\<SID>_Classes".to_string())
        );
    }

    #[test]
    fn build_registry_path_metadata_maps_software_hive_to_hklm() {
        let metadata = build_registry_path_metadata(
            "software",
            r"\CMI-CreateHive\Microsoft\Windows\CurrentVersion",
        );

        assert_eq!(
            metadata.registry_path,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"
        );
        assert_eq!(metadata.hive_mapping, Some("HKLM\\SOFTWARE".to_string()));
    }

    #[test]
    fn build_registry_path_metadata_maps_ntuser_root_to_hkcu() {
        let metadata = build_registry_path_metadata("ntuser", r"\ROOT\Software\Classes");

        assert_eq!(metadata.registry_path, r"HKCU\Software\Classes");
        assert_eq!(metadata.hive_mapping, Some("HKCU".to_string()));
        assert_eq!(metadata.sid, None);
    }

    #[test]
    fn hive_mapping_is_empty_for_unknown_generic_hives() {
        assert_eq!(hive_mapping("registry", None), None);
    }

    #[test]
    fn hive_user_context_from_source_path_handles_service_profiles() {
        assert_eq!(
            hive_user_context_from_source_path(
                r"output\registry-sample-validation-v2\extracted\C\WINDOWS\ServiceProfiles\LocalService\NTUSER.DAT"
            ),
            Some("LocalService".to_string())
        );
    }
}
