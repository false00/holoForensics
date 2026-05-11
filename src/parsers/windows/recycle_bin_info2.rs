use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use serde_json::{Map, Value};

use crate::parser_catalog::ParserFamily;
use crate::parsers::common::{
    Plan, create_output_files, decode_null_terminated, decode_utf16_record, file_name_equals,
    filetime_to_rfc3339, find_paths, new_local_plan, required_root, write_json_line,
};

pub fn build(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    let paths = find_paths(root, |path| file_name_equals(path, "INFO2"))?;
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![new_local_plan(
        family,
        root,
        "Windows.RecycleBin.Info2",
        "windows.recycle_bin.info2",
    )])
}

pub fn collect(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let root = required_root(plan)?;
    let paths = find_paths(&root, |path| file_name_equals(path, "INFO2"))?;
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
    let data = fs::read(path)?;
    if data.len() < 20 {
        return Err(anyhow!("file too small"));
    }

    let signature = u32::from_le_bytes(data[0..4].try_into()?);
    if signature != 5 {
        return Err(anyhow!("unsupported format signature: {signature}"));
    }

    let entry_count = u32::from_le_bytes(data[4..8].try_into()?);
    let entry_size = u32::from_le_bytes(data[12..16].try_into()?) as usize;
    if entry_size != 280 && entry_size != 800 {
        return Err(anyhow!("unsupported file entry size: {entry_size}"));
    }

    let mut records = 0usize;
    let mut processed = 0usize;
    let mut offset = 20usize;
    while offset + entry_size <= data.len() {
        processed += 1;
        if entry_count > 0 && processed > entry_count as usize {
            break;
        }

        let record_data = &data[offset..offset + entry_size];
        let ascii_name = decode_null_terminated(&record_data[..260]);
        let mut original_name = ascii_name.clone();
        if entry_size > 280 {
            let unicode_name = decode_utf16_record(&record_data[280..]);
            if !unicode_name.is_empty() {
                original_name = unicode_name;
            }
        }

        let record_index = u32::from_le_bytes(record_data[260..264].try_into()?);
        let drive_number = u32::from_le_bytes(record_data[264..268].try_into()?);
        let deletion_time = u64::from_le_bytes(record_data[268..276].try_into()?);
        let file_size = u32::from_le_bytes(record_data[276..280].try_into()?);

        if original_name.is_empty() && file_size == 0 && deletion_time == 0 {
            offset += entry_size;
            continue;
        }

        let mut record = Map::new();
        record.insert(
            "data_type".to_string(),
            Value::String("windows:metadata:deleted_item".to_string()),
        );
        record.insert("drive_number".to_string(), Value::from(drive_number));
        record.insert("file_size".to_string(), Value::from(file_size));
        record.insert("offset".to_string(), Value::from(offset as u64));
        record.insert(
            "original_filename".to_string(),
            Value::String(original_name.clone()),
        );
        record.insert("record_index".to_string(), Value::from(record_index));
        record.insert(
            "os_path".to_string(),
            Value::String(path.display().to_string()),
        );
        if let Some(deletion_time) = filetime_to_rfc3339(deletion_time) {
            record.insert("deletion_time".to_string(), Value::String(deletion_time));
        }
        if !ascii_name.is_empty() && ascii_name != original_name {
            record.insert("short_filename".to_string(), Value::String(ascii_name));
        }

        write_json_line(output_file, &record)?;
        records += 1;
        offset += entry_size;
    }

    Ok(records)
}
