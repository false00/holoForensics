use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{Map, Value};

use crate::parser_catalog::ParserFamily;
use crate::parsers::common::{
    Plan, create_output_files, file_name_equals, find_paths, new_local_plan, open_sqlite,
    parse_timeline_application, required_root, sqlite_value_to_json, windows_user_from_path,
    write_json_line,
};

pub fn build(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    let paths = find_paths(root, |path| file_name_equals(path, "ActivitiesCache.db"))?;
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![new_local_plan(
        family,
        root,
        "Windows.Forensics.Timeline.ActivitiesCache",
        "windows.timeline.activities",
    )])
}

pub fn collect(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let root = required_root(plan)?;
    let paths = find_paths(&root, |path| file_name_equals(path, "ActivitiesCache.db"))?;
    let (mut output_file, mut log_file, output_path, log_path) =
        create_output_files(output_dir, &plan.output_name)?;

    let mut records = 0usize;
    for path in &paths {
        match collect_file(&mut output_file, path) {
            Ok(written) => records += written,
            Err(error) => writeln!(log_file, "skip {}: {error}", path.display())?,
        }
    }

    writeln!(log_file, "files={} records={records}", paths.len())?;
    Ok((output_path, log_path))
}

fn collect_file(output_file: &mut File, path: &Path) -> Result<usize> {
    let connection = open_sqlite(path)?;
    let mut statement = connection.prepare("SELECT AppId, LastModifiedTime FROM Activity")?;
    let mut rows = statement.query([])?;

    let user = windows_user_from_path(path);
    let mut records = 0usize;
    while let Some(row) = rows.next()? {
        let app_id: Option<String> = row.get(0)?;
        let app_id = app_id.unwrap_or_default();
        let last_modified = sqlite_value_to_json(row.get_ref(1)?);

        let mut record = Map::new();
        record.insert("user".to_string(), Value::String(user.clone()));
        record.insert(
            "application".to_string(),
            Value::String(parse_timeline_application(&app_id)),
        );
        record.insert("app_id".to_string(), Value::String(app_id));
        record.insert("last_modified".to_string(), last_modified);
        record.insert(
            "os_path".to_string(),
            Value::String(path.display().to_string()),
        );
        write_json_line(output_file, &record)?;
        records += 1;
    }

    Ok(records)
}
