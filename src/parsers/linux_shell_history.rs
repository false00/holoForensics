use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{SecondsFormat, TimeZone, Utc};
use serde_json::{Map, Value};

use crate::parser_catalog::ParserFamily;
use crate::parsers::common::{
    Plan, create_output_files, find_paths, has_matches, new_local_plan, required_root,
    write_json_line,
};

pub fn build(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    let mut plans = Vec::new();

    if has_matches(root, is_history_file)? {
        plans.push(new_local_plan(
            family,
            root,
            "Linux.Shell.History",
            "linux.shell_history",
        ));
    }

    Ok(plans)
}

pub fn collect_shell_history(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let root = required_root(plan)?;
    let paths = find_paths(&root, is_history_file)?;
    let (mut output_file, mut log_file, output_path, log_path) =
        create_output_files(output_dir, &plan.output_name)?;

    let mut records = 0usize;
    for path in &paths {
        match collect_shell_history_file(&mut output_file, path) {
            Ok(written) => records += written,
            Err(error) => writeln!(log_file, "skip {}: {error}", path.display())?,
        }
    }

    writeln!(log_file, "files={} records={records}", paths.len())?;
    Ok((output_path, log_path))
}

fn collect_shell_history_file(output_file: &mut File, path: &Path) -> Result<usize> {
    let contents = String::from_utf8_lossy(&fs::read(path)?).into_owned();
    let user = linux_user_from_path(path);
    let shell = history_shell(path);
    let mut pending_timestamp = None;
    let mut records = 0usize;

    for (line_number, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(timestamp) = parse_bash_timestamp_line(line) {
            pending_timestamp = Some(timestamp);
            continue;
        }

        let (command, inline_timestamp) = match parse_zsh_history_line(line) {
            Some((command, timestamp)) => (command, Some(timestamp)),
            None => (line.to_string(), None),
        };

        let mut record = Map::new();
        record.insert("shell".to_string(), Value::String(shell.clone()));
        record.insert("user".to_string(), Value::String(user.clone()));
        record.insert("command".to_string(), Value::String(command));
        record.insert(
            "line_number".to_string(),
            Value::from((line_number + 1) as u64),
        );
        record.insert(
            "os_path".to_string(),
            Value::String(path.display().to_string()),
        );

        if let Some(timestamp) = inline_timestamp.or_else(|| pending_timestamp.take()) {
            record.insert("timestamp".to_string(), Value::String(timestamp));
        }

        write_json_line(output_file, &record)?;
        records += 1;
    }

    Ok(records)
}

fn is_history_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let lowered = name.to_ascii_lowercase();
    lowered.starts_with('.') && lowered.ends_with("_history")
}

fn parse_bash_timestamp_line(line: &str) -> Option<String> {
    let timestamp = line.strip_prefix('#')?;
    if !timestamp
        .chars()
        .all(|character| character.is_ascii_digit())
    {
        return None;
    }
    unix_seconds_to_rfc3339(timestamp.parse().ok()?)
}

fn parse_zsh_history_line(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix(": ")?;
    let (timestamp, remainder) = rest.split_once(':')?;
    if !timestamp
        .chars()
        .all(|character| character.is_ascii_digit())
    {
        return None;
    }
    let (_, command) = remainder.split_once(';')?;
    let timestamp = unix_seconds_to_rfc3339(timestamp.parse().ok()?)?;
    Some((command.to_string(), timestamp))
}

fn unix_seconds_to_rfc3339(seconds: i64) -> Option<String> {
    if seconds <= 0 {
        return None;
    }
    Utc.timestamp_opt(seconds, 0)
        .single()
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn linux_user_from_path(path: &Path) -> String {
    let normalized = path.display().to_string().replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').collect();

    for index in 0..parts.len().saturating_sub(1) {
        if parts[index].eq_ignore_ascii_case("home") {
            return parts
                .get(index + 1)
                .copied()
                .unwrap_or_default()
                .to_string();
        }
    }

    if normalized.contains("/root/") {
        return "root".to_string();
    }

    String::new()
}

fn history_shell(path: &Path) -> String {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return String::new();
    };

    name.trim_start_matches('.')
        .trim_end_matches("_history")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse_bash_timestamp_line, parse_zsh_history_line};

    #[test]
    fn parse_bash_timestamp_line_handles_epoch_comments() {
        assert_eq!(
            parse_bash_timestamp_line("#1714929600"),
            Some("2024-05-05T17:20:00Z".to_string())
        );
    }

    #[test]
    fn parse_zsh_history_line_extracts_command_and_timestamp() {
        assert_eq!(
            parse_zsh_history_line(": 1714929600:0;ls -la"),
            Some(("ls -la".to_string(), "2024-05-05T17:20:00Z".to_string()))
        );
    }
}
