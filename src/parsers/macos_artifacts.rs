use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{Map, Value};

use crate::parser_catalog::ParserFamily;
use crate::parsers::common::{
    Plan, chrome_time_to_rfc3339_from_i64, cocoa_time_to_rfc3339, create_output_files,
    file_name_equals, find_paths, has_matches, is_mac_chrome_history, mac_user_from_path,
    new_local_plan, open_sqlite, required_root, write_json_line,
};

pub fn build_browser_history(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    if has_matches(root, is_mac_chrome_history)? {
        return Ok(vec![new_local_plan(
            family,
            root,
            "MacOS.Applications.Chrome.History",
            "macos.browser_history.chrome",
        )]);
    }

    Ok(Vec::new())
}

pub fn build_quarantine_events(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    if has_matches(root, |path| {
        file_name_equals(path, "com.apple.LaunchServices.QuarantineEventsV2")
    })? {
        return Ok(vec![new_local_plan(
            family,
            root,
            "MacOS.System.QuarantineEvents",
            "macos.quarantine_events",
        )]);
    }

    Ok(Vec::new())
}

pub fn collect_browser_history(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let root = required_root(plan)?;
    let paths = find_paths(&root, is_mac_chrome_history)?;
    let (mut output_file, mut log_file, output_path, log_path) =
        create_output_files(output_dir, &plan.output_name)?;
    let mut records = 0usize;

    for path in &paths {
        match collect_chrome_history_file(&mut output_file, path) {
            Ok(written) => records += written,
            Err(error) => writeln!(log_file, "skip {}: {error}", path.display())?,
        }
    }

    writeln!(log_file, "files={} records={records}", paths.len())?;
    Ok((output_path, log_path))
}

pub fn collect_quarantine_events(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let root = required_root(plan)?;
    let paths = find_paths(&root, |path| {
        file_name_equals(path, "com.apple.LaunchServices.QuarantineEventsV2")
    })?;
    let (mut output_file, mut log_file, output_path, log_path) =
        create_output_files(output_dir, &plan.output_name)?;
    let mut records = 0usize;

    for path in &paths {
        match collect_quarantine_file(&mut output_file, path) {
            Ok(written) => records += written,
            Err(error) => writeln!(log_file, "skip {}: {error}", path.display())?,
        }
    }

    writeln!(log_file, "files={} records={records}", paths.len())?;
    Ok((output_path, log_path))
}

fn collect_chrome_history_file(output_file: &mut File, path: &Path) -> Result<usize> {
    let connection = open_sqlite(path)?;
    let mut statement = connection
        .prepare("SELECT url, title, visit_count, typed_count, last_visit_time FROM urls")?;
    let mut rows = statement.query([])?;
    let user = mac_user_from_path(path);
    let mut records = 0usize;

    while let Some(row) = rows.next()? {
        let visited_url: String = row.get(0)?;
        let title: Option<String> = row.get(1)?;
        let visit_count: Option<i64> = row.get(2)?;
        let typed_count: Option<i64> = row.get(3)?;
        let last_visit: Option<i64> = row.get(4)?;

        let mut record = Map::new();
        record.insert("browser".to_string(), Value::String("chrome".to_string()));
        record.insert("user".to_string(), Value::String(user.clone()));
        record.insert("visited_url".to_string(), Value::String(visited_url));
        record.insert(
            "title".to_string(),
            Value::String(title.unwrap_or_default()),
        );
        record.insert(
            "visit_count".to_string(),
            Value::from(visit_count.unwrap_or_default()),
        );
        record.insert(
            "typed_count".to_string(),
            Value::from(typed_count.unwrap_or_default()),
        );
        record.insert(
            "os_path".to_string(),
            Value::String(path.display().to_string()),
        );
        if let Some(last_visit_time) = last_visit.and_then(chrome_time_to_rfc3339_from_i64) {
            record.insert(
                "last_visit_time".to_string(),
                Value::String(last_visit_time),
            );
        }
        write_json_line(output_file, &record)?;
        records += 1;
    }

    Ok(records)
}

fn collect_quarantine_file(output_file: &mut File, path: &Path) -> Result<usize> {
    let connection = open_sqlite(path)?;
    let mut statement = connection.prepare("SELECT LSQuarantineTimeStamp, LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineAgentName, LSQuarantineAgentBundleIdentifier, LSQuarantineEventIdentifier FROM LSQuarantineEvent")?;
    let mut rows = statement.query([])?;
    let user = mac_user_from_path(path);
    let mut records = 0usize;

    while let Some(row) = rows.next()? {
        let quarantine_time: Option<f64> = row.get(0)?;
        let download_url: Option<String> = row.get(1)?;
        let origin: Option<String> = row.get(2)?;
        let agent_name: Option<String> = row.get(3)?;
        let agent_bundle: Option<String> = row.get(4)?;
        let event_id: Option<String> = row.get(5)?;

        let mut record = Map::new();
        record.insert("user".to_string(), Value::String(user.clone()));
        record.insert(
            "download_url".to_string(),
            Value::String(download_url.unwrap_or_default()),
        );
        record.insert(
            "origin".to_string(),
            Value::String(origin.unwrap_or_default()),
        );
        record.insert(
            "agent_name".to_string(),
            Value::String(agent_name.unwrap_or_default()),
        );
        record.insert(
            "agent_bundle".to_string(),
            Value::String(agent_bundle.unwrap_or_default()),
        );
        record.insert(
            "event_uuid".to_string(),
            Value::String(event_id.unwrap_or_default()),
        );
        record.insert(
            "os_path".to_string(),
            Value::String(path.display().to_string()),
        );
        if let Some(download_time) = quarantine_time.and_then(cocoa_time_to_rfc3339) {
            record.insert("download_time".to_string(), Value::String(download_time));
        }
        write_json_line(output_file, &record)?;
        records += 1;
    }

    Ok(records)
}
