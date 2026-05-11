use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{Map, Value};

use crate::parser_catalog::ParserFamily;
use crate::parsers::common::{
    Plan, create_output_files, decode_utf16le_string, file_name_equals, filetime_to_rfc3339,
    find_paths, new_local_plan, required_root, write_json_line,
};

pub fn build(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    let paths = find_paths(root, |path| file_name_equals(path, "rp.log"))?;
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![new_local_plan(
        family,
        root,
        "Windows.Forensics.RestorePoint.Log",
        "windows.restore_point.log",
    )])
}

pub fn collect(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let root = required_root(plan)?;
    let paths = find_paths(&root, |path| file_name_equals(path, "rp.log"))?;
    let (mut output_file, mut log_file, output_path, log_path) =
        create_output_files(output_dir, &plan.output_name)?;

    let mut records = 0usize;
    for path in &paths {
        match fs::read(path) {
            Ok(data) => {
                if data.len() < 24 {
                    writeln!(log_file, "skip {}: file too small", path.display())?;
                    continue;
                }

                let mut record = Map::new();
                record.insert(
                    "data_type".to_string(),
                    Value::String("windows:restore_point:info".to_string()),
                );
                record.insert(
                    "description".to_string(),
                    Value::String(decode_utf16le_string(&data[16..data.len() - 8])),
                );
                record.insert(
                    "restore_point_event_type".to_string(),
                    Value::from(u32::from_le_bytes(data[0..4].try_into()?)),
                );
                record.insert(
                    "restore_point_type".to_string(),
                    Value::from(u32::from_le_bytes(data[4..8].try_into()?)),
                );
                record.insert(
                    "sequence_number".to_string(),
                    Value::from(u64::from_le_bytes(data[8..16].try_into()?)),
                );
                if let Some(creation_time) =
                    filetime_to_rfc3339(u64::from_le_bytes(data[data.len() - 8..].try_into()?))
                {
                    record.insert("creation_time".to_string(), Value::String(creation_time));
                }
                record.insert(
                    "os_path".to_string(),
                    Value::String(path.display().to_string()),
                );
                write_json_line(&mut output_file, &record)?;
                records += 1;
            }
            Err(error) => writeln!(log_file, "skip {}: {error}", path.display())?,
        }
    }

    writeln!(log_file, "files={} records={records}", paths.len())?;
    Ok((output_path, log_path))
}
