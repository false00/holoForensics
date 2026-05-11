use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use chrono::{SecondsFormat, TimeZone, Utc};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use serde_json::Value;
use walkdir::WalkDir;

use crate::parser_catalog::ParserFamily;

#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub parser: String,
    pub collection: String,
    pub artifact: String,
    pub output_name: String,
    pub args: BTreeMap<String, String>,
    pub local_collector: Option<String>,
}

pub(crate) fn required_root(plan: &Plan) -> Result<PathBuf> {
    plan.args
        .get("root")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("plan is missing required root argument"))
}

pub(crate) fn new_local_plan(
    family: &ParserFamily,
    root: &Path,
    artifact: &str,
    collector: &str,
) -> Plan {
    let defaults = map_from_pairs([("root", root.display().to_string())]);
    Plan {
        parser: family.name.clone(),
        collection: family.collection.clone(),
        artifact: artifact.to_string(),
        output_name: sanitize_name(artifact),
        args: merged_args(defaults, family, artifact),
        local_collector: Some(collector.to_string()),
    }
}

pub(crate) fn merged_args(
    defaults: BTreeMap<String, String>,
    family: &ParserFamily,
    artifact: &str,
) -> BTreeMap<String, String> {
    let mut merged = defaults;
    for (key, value) in &family.args {
        merged.insert(key.clone(), value.clone());
    }
    if let Some(overrides) = family.per_artifact_args.get(artifact) {
        for (key, value) in overrides {
            merged.insert(key.clone(), value.clone());
        }
    }
    merged
}

pub(crate) fn map_from_pairs<const N: usize>(
    pairs: [(&str, String); N],
) -> BTreeMap<String, String> {
    pairs
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
}

pub(crate) fn create_output_files(
    output_dir: &Path,
    output_name: &str,
) -> Result<(File, File, PathBuf, PathBuf)> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create output directory {}", output_dir.display()))?;
    let output_path = output_dir.join(format!("{output_name}.jsonl"));
    let log_path = output_dir.join(format!("{output_name}.log"));
    let output_file = File::create(&output_path)
        .with_context(|| format!("create output {}", output_path.display()))?;
    let log_file =
        File::create(&log_path).with_context(|| format!("create log {}", log_path.display()))?;
    Ok((output_file, log_file, output_path, log_path))
}

pub(crate) fn write_json_line<T: Serialize>(file: &mut File, value: &T) -> Result<()> {
    serde_json::to_writer(&mut *file, value)?;
    file.write_all(b"\n")?;
    Ok(())
}

pub(crate) fn open_sqlite(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open sqlite {}", path.display()))
}

pub(crate) fn find_paths<F>(root: &Path, matcher: F) -> Result<Vec<PathBuf>>
where
    F: Fn(&Path) -> bool,
{
    let mut paths = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if matcher(path) {
            paths.push(path.to_path_buf());
        }
    }
    Ok(paths)
}

pub(crate) fn has_matches<F>(root: &Path, matcher: F) -> Result<bool>
where
    F: Fn(&Path) -> bool,
{
    Ok(!find_paths(root, matcher)?.is_empty())
}

pub(crate) fn file_name_equals(path: &Path, expected: &str) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

pub(crate) fn normalize_path(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "/")
        .to_ascii_lowercase()
}

pub(crate) fn sanitize_name(value: &str) -> String {
    let mut normalized = value.trim().to_ascii_lowercase();
    normalized = normalized.replace(['.', ' ', '_'], "-");
    let mut output = String::new();
    let mut last_dash = false;
    for character in normalized.chars() {
        let valid =
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-';
        let next = if valid { character } else { '-' };
        if next == '-' {
            if !last_dash {
                output.push(next);
            }
            last_dash = true;
        } else {
            output.push(next);
            last_dash = false;
        }
    }
    let trimmed = output.trim_matches('-');
    if trimmed.is_empty() {
        "artifact".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn windows_user_from_path(path: &Path) -> String {
    let normalized = path.display().to_string().replace('/', "\\");
    let parts: Vec<&str> = normalized.split('\\').collect();
    for index in (0..parts.len().saturating_sub(1)).rev() {
        if parts[index].eq_ignore_ascii_case("Users")
            || parts[index].eq_ignore_ascii_case("Documents and Settings")
        {
            return parts
                .get(index + 1)
                .copied()
                .unwrap_or_default()
                .to_string();
        }
    }
    String::new()
}

pub(crate) fn mac_user_from_path(path: &Path) -> String {
    let normalized = normalize_path(path);
    let parts: Vec<&str> = normalized.split('/').collect();
    for index in (0..parts.len().saturating_sub(1)).rev() {
        if parts[index] == "users" {
            return parts
                .get(index + 1)
                .copied()
                .unwrap_or_default()
                .to_string();
        }
    }
    String::new()
}

pub(crate) fn filetime_to_rfc3339(value: u64) -> Option<String> {
    if value == 0 {
        return None;
    }
    const WINDOWS_EPOCH_OFFSET_100NS: i128 = 116_444_736_000_000_000;
    let unix_100ns = value as i128 - WINDOWS_EPOCH_OFFSET_100NS;
    if unix_100ns <= 0 {
        return None;
    }
    let seconds = (unix_100ns / 10_000_000) as i64;
    let nanoseconds = ((unix_100ns % 10_000_000) * 100) as u32;
    Utc.timestamp_opt(seconds, nanoseconds)
        .single()
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

pub(crate) fn chrome_time_to_rfc3339_from_i64(value: i64) -> Option<String> {
    if value <= 0 {
        return None;
    }
    filetime_to_rfc3339((value as u64) * 10)
}

pub(crate) fn unix_microseconds_to_rfc3339(value: i64) -> Option<String> {
    if value <= 0 {
        return None;
    }
    let seconds = value / 1_000_000;
    let micros = value % 1_000_000;
    Utc.timestamp_opt(seconds, (micros * 1000) as u32)
        .single()
        .map(|datetime| datetime.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

pub(crate) fn cocoa_time_to_rfc3339(value: f64) -> Option<String> {
    if value.abs() < f64::EPSILON {
        return None;
    }
    let whole = value.trunc() as i64;
    let nanos = ((value.fract()) * 1_000_000_000.0).round() as u32;
    Utc.timestamp_opt(978_307_200 + whole, nanos)
        .single()
        .map(|datetime| datetime.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

pub(crate) fn sqlite_value_to_json(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => Value::from(value),
        ValueRef::Real(value) => Value::from(value),
        ValueRef::Text(value) => Value::String(String::from_utf8_lossy(value).into_owned()),
        ValueRef::Blob(value) => Value::String(String::from_utf8_lossy(value).into_owned()),
    }
}

pub(crate) fn parse_timeline_application(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }

    let Ok(decoded) = serde_json::from_str::<Value>(raw) else {
        return raw.to_string();
    };

    match decoded {
        Value::Object(object) => object
            .get("application")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .map(json_value_to_string)
            .unwrap_or_else(|| raw.to_string()),
        Value::Array(values) => values
            .first()
            .map(json_value_to_string)
            .unwrap_or_else(|| raw.to_string()),
        _ => raw.to_string(),
    }
}

fn json_value_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

pub(crate) fn chromium_visit_source(value: i64) -> &'static str {
    match value {
        0 => "Synced",
        1 => "Local",
        2 => "Extension",
        3 => "ImportFromFirefox",
        4 => "ImportFromSafari",
        6 => "ImportFromChromeOrEdge",
        7 => "ImportFromEdgeHTML",
        _ => "Local",
    }
}

pub(crate) fn is_chrome_history(path: &Path) -> bool {
    let normalized = path
        .display()
        .to_string()
        .replace('/', "\\")
        .to_ascii_lowercase();
    if !normalized.ends_with("\\history") {
        return false;
    }
    if normalized.contains("\\microsoft\\edge\\user data\\") {
        return false;
    }
    [
        "\\google\\chrome\\user data\\",
        "\\bravesoftware\\brave-browser\\user data\\",
        "\\vivaldi\\user data\\",
        "\\opera software\\opera",
        "\\chromium\\user data\\",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

pub(crate) fn is_edge_history(path: &Path) -> bool {
    let normalized = path
        .display()
        .to_string()
        .replace('/', "\\")
        .to_ascii_lowercase();
    normalized.ends_with("\\history") && normalized.contains("\\microsoft\\edge\\user data\\")
}

pub(crate) fn is_firefox_history(path: &Path) -> bool {
    let normalized = path
        .display()
        .to_string()
        .replace('/', "\\")
        .to_ascii_lowercase();
    normalized.ends_with("\\places.sqlite") && normalized.contains("\\mozilla\\firefox\\profiles\\")
}

pub(crate) fn is_mac_chrome_history(path: &Path) -> bool {
    let normalized = normalize_path(path);
    normalized.ends_with("/history")
        && normalized.contains("/library/application support/google/chrome/")
}

pub(crate) fn decode_utf16le_string(data: &[u8]) -> String {
    let mut code_units = Vec::new();
    let mut offset = 0usize;
    while offset + 1 < data.len() {
        let value = u16::from_le_bytes([data[offset], data[offset + 1]]);
        if value == 0 {
            break;
        }
        code_units.push(value);
        offset += 2;
    }
    String::from_utf16_lossy(&code_units)
}

pub(crate) fn decode_utf16_record(data: &[u8]) -> String {
    decode_utf16le_string(data)
}

pub(crate) fn decode_null_terminated(data: &[u8]) -> String {
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}
