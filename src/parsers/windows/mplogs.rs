use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::parser_catalog::ParserFamily;
use crate::parsers::common::{
    Plan, create_output_files, find_paths, has_matches, new_local_plan, required_root,
    write_json_line,
};

const MPLOG_DATA_TYPE: &str = "windows:defender:mplog:line";

#[derive(Debug, Clone, Serialize)]
pub struct MpLogRecord {
    pub data_type: String,
    pub source_file: String,
    pub os_path: String,
    pub source_sha256: String,
    pub encoding: String,
    pub decode_lossy: bool,
    pub line_no: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_assumption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hresult: Option<String>,
    pub fields: BTreeMap<String, String>,
    pub message: String,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedText {
    text: String,
    encoding: String,
    lossy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTimestamp {
    raw: String,
    utc: Option<String>,
    assumption: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedFileSummary {
    records: usize,
    encoding: String,
    lossy: bool,
}

pub fn build(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    if !has_matches(root, is_mplog_file)? {
        return Ok(Vec::new());
    }

    Ok(vec![new_local_plan(
        family,
        root,
        "Windows.Defender.MPLog",
        "windows.mplogs",
    )])
}

pub fn collect(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let root = required_root(plan)?;
    let paths = find_paths(&root, is_mplog_file)?;
    let (mut output_file, mut log_file, output_path, log_path) =
        create_output_files(output_dir, &plan.output_name)?;

    let mut records = 0usize;
    for path in &paths {
        match collect_mplog_file(&mut output_file, path) {
            Ok(summary) => {
                records += summary.records;
                writeln!(
                    log_file,
                    "parsed {} encoding={} lossy={} records={}",
                    path.display(),
                    summary.encoding,
                    summary.lossy,
                    summary.records
                )?;
            }
            Err(error) => writeln!(log_file, "skip {}: {error}", path.display())?,
        }
    }

    writeln!(log_file, "files={} records={records}", paths.len())?;
    Ok((output_path, log_path))
}

fn collect_mplog_file(output_file: &mut File, path: &Path) -> Result<ParsedFileSummary> {
    let bytes = fs::read(path)?;
    let decoded = decode_mplog_bytes(&bytes);
    let source_sha256 = sha256_hex(&bytes);
    let records = parse_mplog_text(
        &decoded.text,
        &path.display().to_string(),
        &source_sha256,
        &decoded.encoding,
        decoded.lossy,
    );
    let record_count = records.len();

    for record in records {
        write_json_line(output_file, &record)?;
    }

    Ok(ParsedFileSummary {
        records: record_count,
        encoding: decoded.encoding,
        lossy: decoded.lossy,
    })
}

fn parse_mplog_text(
    text: &str,
    source_file: &str,
    source_sha256: &str,
    encoding: &str,
    decode_lossy: bool,
) -> Vec<MpLogRecord> {
    let mut records: Vec<MpLogRecord> = Vec::new();

    for (index, line) in text.lines().enumerate() {
        let line_no = index + 1;
        let trimmed = line.trim_end();
        if trimmed.trim().is_empty() {
            continue;
        }

        if should_merge_continuation(trimmed) {
            if let Some(last) = records.last_mut() {
                last.message.push('\n');
                last.message.push_str(trimmed.trim());
                last.raw.push('\n');
                last.raw.push_str(trimmed);
                if last.path.is_none() {
                    last.path = infer_path(trimmed, &last.fields);
                }
                continue;
            }
        }

        let (timestamp, remainder) = parse_timestamp_prefix(trimmed);
        let mut fields = BTreeMap::new();
        let (component, explicit_level, body) =
            split_component_prefix(remainder.trim_start(), &mut fields);
        merge_extracted_fields(&mut fields, body);
        infer_additional_fields(&mut fields, trimmed);

        let level = explicit_level.or_else(|| infer_level(trimmed, &fields));
        let event_type = classify_event(trimmed, &fields, component.as_deref(), level.as_deref());

        records.push(MpLogRecord {
            data_type: MPLOG_DATA_TYPE.to_string(),
            source_file: source_file.to_string(),
            os_path: source_file.to_string(),
            source_sha256: source_sha256.to_string(),
            encoding: encoding.to_string(),
            decode_lossy,
            line_no,
            timestamp_raw: timestamp.as_ref().map(|value| value.raw.clone()),
            timestamp_utc: timestamp.as_ref().and_then(|value| value.utc.clone()),
            timestamp_assumption: timestamp.and_then(|value| value.assumption),
            level,
            component,
            threat_name: get_field_any(&fields, &["threat_name", "threat", "malware"]),
            threat_id: get_field_any(&fields, &["threat_id"]),
            path: infer_path(trimmed, &fields),
            process: get_field_any(&fields, &["process"]),
            action: infer_action(trimmed, &fields),
            result: get_field_any(&fields, &["result", "status"]),
            hresult: get_field_any(&fields, &["hresult", "error", "error_code"]),
            event_type,
            fields,
            message: trimmed.trim().to_string(),
            raw: trimmed.to_string(),
        });
    }

    records
}

fn is_mplog_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|value| {
            let lowered = value.to_ascii_lowercase();
            lowered.starts_with("mplog") && lowered.ends_with(".log")
        })
        .unwrap_or(false)
}

fn decode_mplog_bytes(bytes: &[u8]) -> DecodedText {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return match String::from_utf8(bytes[3..].to_vec()) {
            Ok(text) => DecodedText {
                text,
                encoding: "utf-8-bom".to_string(),
                lossy: false,
            },
            Err(_) => DecodedText {
                text: String::from_utf8_lossy(&bytes[3..]).into_owned(),
                encoding: "utf-8-bom".to_string(),
                lossy: true,
            },
        };
    }

    if bytes.starts_with(&[0xFF, 0xFE]) {
        return DecodedText {
            text: decode_utf16le_bytes(&bytes[2..]),
            encoding: "utf-16le-bom".to_string(),
            lossy: false,
        };
    }

    let null_count = bytes.iter().take(2000).filter(|byte| **byte == 0).count();
    if null_count > 100 {
        return DecodedText {
            text: decode_utf16le_bytes(bytes),
            encoding: "utf-16le".to_string(),
            lossy: false,
        };
    }

    match String::from_utf8(bytes.to_vec()) {
        Ok(text) => DecodedText {
            text,
            encoding: "utf-8".to_string(),
            lossy: false,
        },
        Err(_) => DecodedText {
            text: String::from_utf8_lossy(bytes).into_owned(),
            encoding: "utf-8-lossy".to_string(),
            lossy: true,
        },
    }
}

fn decode_utf16le_bytes(bytes: &[u8]) -> String {
    let mut code_units = Vec::with_capacity(bytes.len() / 2);
    let mut offset = 0usize;
    while offset + 1 < bytes.len() {
        code_units.push(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]));
        offset += 2;
    }
    String::from_utf16_lossy(&code_units)
}

fn parse_timestamp_prefix(line: &str) -> (Option<ParsedTimestamp>, &str) {
    let Some(captures) = timestamp_prefix_re().captures(line) else {
        return (None, line);
    };
    let Some(match_value) = captures.name("ts") else {
        return (None, line);
    };
    let raw = match_value.as_str();
    let parsed = parse_timestamp_raw(raw);
    let remainder = line[match_value.end()..].trim_start();
    (Some(parsed), remainder)
}

fn parse_timestamp_raw(raw: &str) -> ParsedTimestamp {
    if has_explicit_timezone(raw) {
        let normalized = if raw.contains(' ') {
            raw.replacen(' ', "T", 1)
        } else {
            raw.to_string()
        };
        if let Ok(value) = DateTime::parse_from_rfc3339(&normalized) {
            return ParsedTimestamp {
                raw: raw.to_string(),
                utc: Some(value.with_timezone(&Utc).to_rfc3339()),
                assumption: None,
            };
        }
    }

    for format in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m-%d-%Y %H:%M:%S%.f",
        "%m/%d/%Y %H:%M:%S%.f",
        "%m-%d-%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ] {
        if NaiveDateTime::parse_from_str(raw, format).is_ok() {
            return ParsedTimestamp {
                raw: raw.to_string(),
                utc: None,
                assumption: Some("local_time_unspecified".to_string()),
            };
        }
    }

    ParsedTimestamp {
        raw: raw.to_string(),
        utc: None,
        assumption: Some("unparsed_timestamp".to_string()),
    }
}

fn has_explicit_timezone(value: &str) -> bool {
    if value.ends_with('Z') {
        return true;
    }
    timezone_suffix_re().is_match(value)
}

fn split_component_prefix<'a>(
    line: &'a str,
    fields: &mut BTreeMap<String, String>,
) -> (Option<String>, Option<String>, &'a str) {
    let trimmed = line.trim_start();

    if let Some(stripped) = trimmed.strip_prefix("WARNING:") {
        return (None, Some("Warning".to_string()), stripped.trim_start());
    }
    if let Some(stripped) = trimmed.strip_prefix("ERROR:") {
        return (None, Some("Error".to_string()), stripped.trim_start());
    }
    if let Some(stripped) = trimmed.strip_prefix("INFO:") {
        return (None, Some("Info".to_string()), stripped.trim_start());
    }

    if let Some(captures) = bracket_component_re().captures(trimmed) {
        let component = captures
            .name("component")
            .map(|value| value.as_str().to_string());
        if let Some(subcomponent) = captures.name("subcomponent") {
            fields.insert(
                "subcomponent".to_string(),
                subcomponent.as_str().to_string(),
            );
        }
        let rest = captures
            .name("rest")
            .map(|value| value.as_str())
            .unwrap_or("");
        return (component, None, rest.trim_start());
    }

    if let Some(captures) = double_colon_component_re().captures(trimmed) {
        let component = captures
            .name("component")
            .map(|value| value.as_str().to_string());
        if let Some(operation) = captures.name("operation") {
            fields.insert(
                "operation".to_string(),
                normalize_field_value(operation.as_str()),
            );
        }
        let rest = captures
            .name("rest")
            .map(|value| value.as_str())
            .unwrap_or("");
        return (component, None, rest.trim_start());
    }

    if let Some(captures) = colon_component_re().captures(trimmed) {
        let component = captures
            .name("component")
            .map(|value| value.as_str().to_string());
        let rest = captures
            .name("rest")
            .map(|value| value.as_str())
            .unwrap_or("");
        return (component, None, rest.trim_start());
    }

    (None, None, trimmed)
}

fn merge_extracted_fields(fields: &mut BTreeMap<String, String>, line: &str) {
    for (key, value) in extract_fields(line) {
        let normalized_key = normalize_field_key(&key);
        let normalized_value = normalize_field_value(&value);
        if !normalized_key.is_empty() && !normalized_value.is_empty() {
            fields.entry(normalized_key).or_insert(normalized_value);
        }
    }
}

fn extract_fields(line: &str) -> Vec<(String, String)> {
    let bytes = line.as_bytes();
    let mut index = 0usize;
    let mut fields = Vec::new();

    while index < bytes.len() {
        while index < bytes.len() && is_field_separator(bytes[index]) {
            index += 1;
        }
        if index >= bytes.len() || !bytes[index].is_ascii_alphabetic() {
            index += 1;
            continue;
        }

        let key_start = index;
        let mut delimiter = None;
        while index < bytes.len() {
            match bytes[index] {
                b'=' | b':' => {
                    delimiter = Some(index);
                    break;
                }
                b'\r' | b'\n' | b',' | b';' => break,
                _ => index += 1,
            }
        }

        let Some(delimiter_index) = delimiter else {
            break;
        };

        let raw_key = line[key_start..delimiter_index].trim();
        if !looks_like_field_key(raw_key) {
            index = key_start + 1;
            continue;
        }

        index = delimiter_index + 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }

        let value_start = index;
        let value_end = find_value_end(line, value_start);
        let value = line[value_start..value_end]
            .trim()
            .trim_end_matches(',')
            .trim_end_matches(';')
            .to_string();
        if !value.is_empty() {
            fields.push((raw_key.to_string(), value));
        }

        index = value_end;
        while index < bytes.len() && is_field_separator(bytes[index]) {
            index += 1;
        }
    }

    fields
}

fn find_value_end(line: &str, value_start: usize) -> usize {
    let bytes = line.as_bytes();
    if bytes[value_start] == b'"' {
        let mut index = value_start + 1;
        while index < bytes.len() {
            if bytes[index] == b'"' {
                return index + 1;
            }
            index += 1;
        }
        return bytes.len();
    }

    if bytes[value_start] == b'{' {
        let mut index = value_start + 1;
        while index < bytes.len() {
            if bytes[index] == b'}' {
                return index + 1;
            }
            index += 1;
        }
        return bytes.len();
    }

    let mut index = value_start;
    while index < bytes.len() {
        match bytes[index] {
            b',' | b';' | b'\r' | b'\n' => return index,
            byte if byte.is_ascii_whitespace()
                && next_token_looks_like_field_key(line, index + 1) =>
            {
                return index;
            }
            _ => index += 1,
        }
    }
    bytes.len()
}

fn next_token_looks_like_field_key(line: &str, start: usize) -> bool {
    if start >= line.len() {
        return false;
    }

    let bytes = line.as_bytes();
    let mut index = start;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if index >= bytes.len() || !bytes[index].is_ascii_alphabetic() {
        return false;
    }

    let key_start = index;
    while index < bytes.len() {
        match bytes[index] {
            b'=' | b':' => {
                let key = line[key_start..index].trim();
                return looks_like_field_key(key);
            }
            b',' | b';' | b'\r' | b'\n' => return false,
            _ => index += 1,
        }
    }
    false
}

fn looks_like_field_key(value: &str) -> bool {
    if value.len() < 2 || value.contains(['/', '\\', '"']) {
        return false;
    }
    value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, ' ' | '_' | '.' | '-')
    })
}

fn is_field_separator(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b',' | b';')
}

fn infer_additional_fields(fields: &mut BTreeMap<String, String>, line: &str) {
    if let Some(captures) = original_name_re().captures(line) {
        if let Some(name) = captures.name("name") {
            fields
                .entry("original_file_name".to_string())
                .or_insert_with(|| name.as_str().to_string());
        }
        if let Some(path) = captures.name("path") {
            fields
                .entry("path".to_string())
                .or_insert_with(|| path.as_str().to_string());
        }
    }

    if !fields.contains_key("hresult") {
        if let Some(captures) = hresult_re().captures(line) {
            if let Some(value) = captures.name("value") {
                fields.insert("hresult".to_string(), value.as_str().to_string());
            }
        }
    }

    if !fields.contains_key("path") {
        if let Some(path) = infer_path(line, fields) {
            fields.insert("path".to_string(), path);
        }
    }
}

fn normalize_field_key(key: &str) -> String {
    let lowered = key.trim().to_ascii_lowercase();
    match lowered.as_str() {
        "hr" => "hresult".to_string(),
        "threatid" | "threat id" => "threat_id".to_string(),
        "threatname" | "threat name" => "threat_name".to_string(),
        "action taken" => "action".to_string(),
        "statusex" => "status_ex".to_string(),
        "sigseq" => "signature_sequence".to_string(),
        "sigsha" => "signature_sha".to_string(),
        "fileid" => "file_id".to_string(),
        "scanrequest" => "scan_request".to_string(),
        "desiredaccess" => "desired_access".to_string(),
        "fileattributes" => "file_attributes".to_string(),
        "scanattributes" => "scan_attributes".to_string(),
        "accessstateflags" => "access_state_flags".to_string(),
        "iostatusblockfornewfile" => "io_status_block_for_new_file".to_string(),
        "backingfileinfo" => "backing_file_info".to_string(),
        "quarantine id" => "quarantine_id".to_string(),
        "engine version" => "engine_version".to_string(),
        "platform version" => "platform_version".to_string(),
        "security intelligence version" => "security_intelligence_version".to_string(),
        "path" | "file" | "filename" | "resource" | "target" => "path".to_string(),
        _ => to_snake_case(&lowered),
    }
}

fn normalize_field_value(value: &str) -> String {
    value.trim().trim_matches('"').to_string()
}

fn to_snake_case(value: &str) -> String {
    let mut output = String::new();
    let mut last_was_underscore = false;
    for character in value.chars() {
        let next = if character.is_ascii_alphanumeric() {
            character.to_ascii_lowercase()
        } else {
            '_'
        };
        if next == '_' {
            if !last_was_underscore {
                output.push(next);
            }
            last_was_underscore = true;
        } else {
            output.push(next);
            last_was_underscore = false;
        }
    }
    output.trim_matches('_').to_string()
}

fn infer_level(line: &str, fields: &BTreeMap<String, String>) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    if lower.starts_with("warning:") || lower.contains(" warning") {
        return Some("Warning".to_string());
    }
    if lower.starts_with("error:")
        || lower.contains("reporterror")
        || lower.contains("failed")
        || lower.contains("failure")
        || lower.contains("unsuccessful")
        || has_nonzero_hresult(fields)
    {
        return Some("Error".to_string());
    }
    if lower.starts_with("info:") {
        return Some("Info".to_string());
    }
    None
}

fn has_nonzero_hresult(fields: &BTreeMap<String, String>) -> bool {
    let Some(value) = get_field_any(fields, &["hresult"]) else {
        return false;
    };
    !matches!(value.as_str(), "0" | "0x0" | "0x00000000")
}

fn classify_event(
    line: &str,
    fields: &BTreeMap<String, String>,
    component: Option<&str>,
    level: Option<&str>,
) -> String {
    let lower = line.to_ascii_lowercase();

    if lower.contains("quarantine") {
        return "Quarantine".to_string();
    }
    if fields.contains_key("threat_name")
        || fields.contains_key("threat_id")
        || lower.contains("threat")
        || lower.contains("malware")
    {
        return "Threat".to_string();
    }
    if lower.contains("detected") {
        return "Detection".to_string();
    }
    if lower.contains("remediat") || lower.contains("clean") {
        return "Remediation".to_string();
    }
    if lower.contains("scan") || fields.contains_key("scan_request") {
        return "Scan".to_string();
    }
    if lower.contains("tamper") {
        return "TamperProtection".to_string();
    }
    if lower.contains("cloud") || lower.contains("maps") {
        return "CloudProtection".to_string();
    }
    if lower.contains("exclusion") || lower.contains("excluded") {
        return "Exclusion".to_string();
    }
    if lower.contains("security intelligence")
        || lower.contains("signature")
        || lower.contains("sigseq")
        || lower.contains("sigsha")
        || lower.contains("engine version")
        || lower.contains("platform version")
        || lower.contains("definition")
    {
        return "Update".to_string();
    }
    if matches_component(component, &["rtp", "mprtp", "mini-filter"])
        || lower.contains("[rtp]")
        || lower.contains("real-time")
        || lower.contains("realtime")
    {
        return "RealTimeProtection".to_string();
    }
    if lower.contains("platform") {
        return "Platform".to_string();
    }
    if matches_component(component, &["engine"]) || lower.starts_with("engine:") {
        return "Engine".to_string();
    }
    if matches!(level, Some("Error")) {
        return "Error".to_string();
    }
    if matches!(level, Some("Warning")) {
        return "Warning".to_string();
    }
    if matches!(level, Some("Info")) {
        return "Info".to_string();
    }
    "Unknown".to_string()
}

fn matches_component(component: Option<&str>, expected: &[&str]) -> bool {
    component
        .map(|value| {
            expected
                .iter()
                .any(|candidate| value.eq_ignore_ascii_case(candidate))
        })
        .unwrap_or(false)
}

fn infer_action(line: &str, fields: &BTreeMap<String, String>) -> Option<String> {
    if let Some(action) = get_field_any(fields, &["action", "remediation"]) {
        return Some(action);
    }

    let lower = line.to_ascii_lowercase();
    if lower.starts_with("beginning quarantine") {
        return Some("begin_quarantine_recovery".to_string());
    }
    if lower.starts_with("finished quarantine") {
        return Some("finish_quarantine_recovery".to_string());
    }
    None
}

fn infer_path(line: &str, fields: &BTreeMap<String, String>) -> Option<String> {
    if let Some(path) = get_field_any(fields, &["path", "file", "filename", "resource", "target"]) {
        return Some(path);
    }
    if let Some(captures) = quoted_windows_path_re().captures(line) {
        if let Some(path) = captures.name("path") {
            return Some(path.as_str().to_string());
        }
    }
    if let Some(captures) = device_path_re().captures(line) {
        if let Some(path) = captures.name("path") {
            return Some(path.as_str().trim_end_matches('.').to_string());
        }
    }
    if let Some(captures) = plain_windows_path_re().captures(line.trim()) {
        if let Some(path) = captures.name("path") {
            return Some(path.as_str().to_string());
        }
    }
    None
}

fn get_field_any(fields: &BTreeMap<String, String>, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(value) = fields.get(*name) {
            return Some(value.clone());
        }
    }
    None
}

fn should_merge_continuation(line: &str) -> bool {
    line.starts_with(char::is_whitespace)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn timestamp_prefix_re() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?|\d{1,2}[-/]\d{1,2}[-/]\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
            .expect("timestamp regex should compile")
    })
}

fn timezone_suffix_re() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"[+-]\d{2}:\d{2}$").expect("timezone suffix regex should compile")
    })
}

fn bracket_component_re() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"^\[(?P<component>[^\]]+)\]\s*(?:\[(?P<subcomponent>[^\]]+)\]\s*)?(?P<rest>.*)$",
        )
        .expect("bracket component regex should compile")
    })
}

fn double_colon_component_re() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"^(?P<component>[A-Za-z][A-Za-z0-9_.-]{1,40})::(?:(?P<operation>[A-Za-z][A-Za-z0-9_.-]{1,40})\s+)?(?P<rest>.*)$",
        )
        .expect("double colon component regex should compile")
    })
}

fn colon_component_re() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"^(?P<component>[A-Za-z][A-Za-z0-9_.-]{1,40}):(?P<rest>.*)$")
            .expect("colon component regex should compile")
    })
}

fn original_name_re() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"Setting original file name \"(?P<name>[^\"]*)\" for \"(?P<path>[A-Za-z]:\\[^\"]+)\""#)
            .expect("original name regex should compile")
    })
}

fn quoted_windows_path_re() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"\"(?P<path>[A-Za-z]:\\[^\"]+)\""#).expect("quoted path regex should compile")
    })
}

fn device_path_re() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?P<path>\\Device\\[^,\r\n]+)").expect("device path regex should compile")
    })
}

fn plain_windows_path_re() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?P<path>[A-Za-z]:\\[^,;\r\n]+)").expect("plain path regex should compile")
    })
}

fn hresult_re() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?:hr|hresult)\s*=\s*(?P<value>0x[0-9a-fA-F]+|\d+)")
            .expect("hresult regex should compile")
    })
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use anyhow::Result;

    use super::{
        MpLogRecord, build, collect, decode_mplog_bytes, is_mplog_file, parse_mplog_text,
        sha256_hex,
    };
    use crate::parser_catalog::ParserFamily;
    use crate::parsers::common::Plan;

    #[test]
    fn mplogs_decode_detects_utf16le_bom() {
        let bytes = [
            0xFF, 0xFE, 0x32, 0x00, 0x30, 0x00, 0x32, 0x00, 0x36, 0x00, 0x0D, 0x00, 0x0A, 0x00,
        ];

        let decoded = decode_mplog_bytes(&bytes);

        assert_eq!(decoded.encoding, "utf-16le-bom");
        assert!(!decoded.lossy);
        assert!(decoded.text.starts_with("2026"));
    }

    #[test]
    fn mplogs_parser_classifies_actual_sample_shapes() {
        let text = concat!(
            "2026-04-27T09:00:26.649 Engine:Setting original file name \"dwmscenei\" for \"c:\\program files\\windowsapps\\example\\dwmscenei.dll\", hr=0x0\n",
            "2026-04-27T11:47:30.775 [RTP] [MpRtp] Engine VFZ lofi/sample/expensive: \\Device\\HarddiskVolume4\\Users\\juanc\\AppData\\Local\\OpenCode\\OpenCode.exe. status=0x40050000, statusex=0x0, threatid=0x80000000, sigseq=0x5551744973f\n",
            "  C:\\Users\\juanc\\arete\\bloktd\\arete-analytica-threat-intelligence-collector\n",
            "2026-04-30T05:25:08.497 WARNING: the previous service shutdown was not expected.\n",
            "Beginning quarantine recovery\n",
            "Quarantine ID:{00000000-0000-0000-0000-000000000000}\n",
            "IDynamicConfig::ReportError value=MpCloudBlockLevel hr=0x8007000d\n",
        );
        let records = parse_mplog_text(text, "sample.log", "abc123", "utf-16le-bom", false);

        assert_eq!(records.len(), 6);

        let engine = &records[0];
        assert_eq!(engine.component.as_deref(), Some("Engine"));
        assert_eq!(engine.event_type, "Engine");
        assert_eq!(engine.hresult.as_deref(), Some("0x0"));
        assert_eq!(
            engine.path.as_deref(),
            Some("c:\\program files\\windowsapps\\example\\dwmscenei.dll")
        );
        assert!(!engine.fields.contains_key("c"));

        let threat = &records[1];
        assert_eq!(threat.component.as_deref(), Some("RTP"));
        assert_eq!(threat.event_type, "Threat");
        assert_eq!(threat.threat_id.as_deref(), Some("0x80000000"));
        assert!(
            threat
                .message
                .contains("arete-analytica-threat-intelligence-collector")
        );

        let warning = &records[2];
        assert_eq!(warning.level.as_deref(), Some("Warning"));
        assert_eq!(warning.event_type, "Warning");

        let quarantine = &records[3];
        assert_eq!(quarantine.event_type, "Quarantine");
        assert_eq!(
            quarantine.action.as_deref(),
            Some("begin_quarantine_recovery")
        );

        let quarantine_id = &records[4];
        assert_eq!(quarantine_id.event_type, "Quarantine");
        assert_eq!(
            quarantine_id
                .fields
                .get("quarantine_id")
                .map(String::as_str),
            Some("{00000000-0000-0000-0000-000000000000}")
        );

        let cloud = &records[5];
        assert_eq!(cloud.component.as_deref(), Some("IDynamicConfig"));
        assert_eq!(cloud.level.as_deref(), Some("Error"));
        assert_eq!(cloud.event_type, "CloudProtection");
        assert_eq!(cloud.hresult.as_deref(), Some("0x8007000d"));
    }

    #[test]
    fn mplogs_parser_detects_mplog_file_names() {
        assert!(is_mplog_file(Path::new("MPLog-20260427-123144.log")));
        assert!(is_mplog_file(Path::new("mplog-test.LOG")));
        assert!(!is_mplog_file(Path::new("collection.log")));
    }

    #[test]
    fn mplogs_build_and_collect_parse_utf16_sample_file() -> Result<()> {
        let root = unique_temp_dir("mplogs-root");
        let output_dir = unique_temp_dir("mplogs-output");
        let sample_path = root
            .join("C")
            .join("ProgramData")
            .join("Microsoft")
            .join("Windows Defender")
            .join("Support");
        fs::create_dir_all(&sample_path)?;

        let file_path = sample_path.join("MPLog-20260427-123144.log");
        let text = concat!(
            "2026-04-27T09:00:26.649 Engine:Setting original file name \"dwmscenei\" for \"c:\\program files\\windowsapps\\example\\dwmscenei.dll\", hr=0x0\r\n",
            "Beginning quarantine recovery\r\n",
        );
        fs::write(&file_path, utf16le_bom_bytes(text))?;

        let family = ParserFamily {
            name: "windows_mplogs".to_string(),
            collection: "windows_mplogs_collection".to_string(),
            enabled: true,
            ..ParserFamily::default()
        };
        let plans = build(&root, &family)?;
        assert_eq!(plans.len(), 1);

        let (jsonl_path, log_path) = collect(&plans[0], &output_dir)?;
        let output = fs::read_to_string(&jsonl_path)?;
        let log = fs::read_to_string(&log_path)?;

        assert!(output.contains("windows:defender:mplog:line"));
        assert!(output.contains("utf-16le-bom"));
        assert!(output.contains("Quarantine"));
        assert!(log.contains("records=2"));

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&output_dir);
        Ok(())
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        env::temp_dir().join(format!("holo-forensics-{prefix}-{suffix}"))
    }

    fn utf16le_bom_bytes(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[allow(dead_code)]
    fn _record_paths(records: &[MpLogRecord]) -> Vec<Option<String>> {
        records.iter().map(|record| record.path.clone()).collect()
    }

    #[allow(dead_code)]
    fn _plan_output_name(plan: &Plan) -> &str {
        &plan.output_name
    }

    #[test]
    fn mplogs_sha256_hex_matches_known_value() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
