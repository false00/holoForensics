use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use artemis_forensics::core::artemis_collection;
use artemis_forensics::structs::toml::{ArtemisToml, Artifacts as ArtemisArtifacts, Output};
use serde_json::{Value, json};

use crate::parser_catalog::ParserFamily;
use crate::parsers::common::{
    Plan, create_output_files, file_name_equals, find_paths, map_from_pairs, merged_args,
    normalize_path, required_root, sanitize_name,
};

pub fn build_prefetch(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.Prefetch",
        "windows.artemis.prefetch",
        is_prefetch_file,
    )
}

pub fn collect_prefetch(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_directory_batch(plan, output_dir, is_prefetch_file, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "prefetch",
            "prefetch": {
                "alt_dir": source_path.display().to_string()
            }
        }))
    })
}

pub fn build_event_logs(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.EventLogs",
        "windows.artemis.event_logs",
        is_event_log_file,
    )
}

pub fn collect_event_logs(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_directory_batch(plan, output_dir, is_event_log_file, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "eventlogs",
            "eventlogs": {
                "alt_file": null,
                "alt_dir": source_path.display().to_string(),
                "include_templates": false,
                "dump_templates": false,
                "alt_template_file": null,
                "only_templates": false
            }
        }))
    })
}

pub fn build_userassist(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.Registry.UserAssist",
        "windows.artemis.userassist",
        is_ntuser_hive,
    )
}

pub fn collect_userassist(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_ntuser_hive, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "userassist",
            "userassist": {
                "resolve_descriptions": false,
                "alt_file": source_path.display().to_string()
            }
        }))
    })
}

pub fn build_shimcache(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.Registry.Shimcache",
        "windows.artemis.shimcache",
        is_system_hive,
    )
}

pub fn collect_shimcache(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_system_hive, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "shimcache",
            "shimcache": {
                "alt_file": source_path.display().to_string()
            }
        }))
    })
}

pub fn build_shellbags(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.Registry.Shellbags",
        "windows.artemis.shellbags",
        is_shellbags_hive,
    )
}

pub fn collect_shellbags(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_shellbags_hive, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "shellbags",
            "shellbags": {
                "resolve_guids": false,
                "alt_file": source_path.display().to_string()
            }
        }))
    })
}

pub fn build_amcache(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.Registry.Amcache",
        "windows.artemis.amcache",
        is_amcache_hive,
    )
}

pub fn collect_amcache(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_amcache_hive, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "amcache",
            "amcache": {
                "alt_file": source_path.display().to_string()
            }
        }))
    })
}

pub fn build_shortcuts(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.Shortcuts",
        "windows.artemis.shortcuts",
        is_shortcut_file,
    )
}

pub fn collect_shortcuts(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_directory_batch(plan, output_dir, is_shortcut_file, |source_path| {
        let glob = source_path.join("*.lnk");
        artifact_from_json(json!({
            "artifact_name": "shortcuts",
            "shortcuts": {
                "dir": glob.display().to_string()
            }
        }))
    })
}

pub fn build_srum(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.SRUM",
        "windows.artemis.srum",
        is_srum_database,
    )
}

pub fn collect_srum(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_srum_database, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "srum",
            "srum": {
                "alt_file": source_path.display().to_string()
            }
        }))
    })
}

pub fn build_users(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.Users",
        "windows.artemis.users",
        is_sam_hive,
    )
}

pub fn collect_users(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_sam_hive, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "users-windows",
            "users_windows": {
                "alt_file": source_path.display().to_string()
            }
        }))
    })
}

pub fn build_services(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.Services",
        "windows.artemis.services",
        is_system_hive,
    )
}

pub fn collect_services(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_system_hive, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "services",
            "services": {
                "alt_file": source_path.display().to_string()
            }
        }))
    })
}

pub fn build_jump_lists(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.JumpLists",
        "windows.artemis.jump_lists",
        is_jump_list_file,
    )
}

pub fn collect_jump_lists(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_jump_list_file, jump_lists_artifact)
}

pub fn build_recycle_bin(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.RecycleBin",
        "windows.artemis.recycle_bin",
        is_recycle_bin_metadata_file,
    )
}

pub fn collect_recycle_bin(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(
        plan,
        output_dir,
        is_recycle_bin_metadata_file,
        |source_path| {
            artifact_from_json(json!({
                "artifact_name": "recyclebin",
                "recyclebin": {
                    "alt_file": source_path.display().to_string()
                }
            }))
        },
    )
}

pub fn build_scheduled_tasks(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.ScheduledTasks",
        "windows.artemis.scheduled_tasks",
        is_scheduled_task_file,
    )
}

pub fn collect_scheduled_tasks(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_scheduled_task_file, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "tasks",
            "tasks": {
                "alt_file": source_path.display().to_string()
            }
        }))
    })
}

pub fn build_wmi_persistence(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.WMIPersistence",
        "windows.artemis.wmi_persistence",
        is_wmi_repository_file,
    )
}

pub fn collect_wmi_persistence(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_directory_batch(plan, output_dir, is_wmi_repository_file, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "wmipersist",
            "wmipersist": {
                "alt_dir": source_path.display().to_string()
            }
        }))
    })
}

pub fn build_mft(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.MFT",
        "windows.artemis.mft",
        is_mft_file,
    )
}

pub fn collect_mft(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_mft_file, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "mft",
            "mft": {
                "alt_file": source_path.display().to_string(),
                "alt_drive": null
            }
        }))
    })
}

pub fn build_bits(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.BITS",
        "windows.artemis.bits",
        is_bits_database,
    )
}

pub fn collect_bits(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_bits_database, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "bits",
            "bits": {
                "alt_file": source_path.display().to_string(),
                "carve": false
            }
        }))
    })
}

pub fn build_search(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.Search",
        "windows.artemis.search",
        is_search_database,
    )
}

pub fn collect_search(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_search_database, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "search",
            "search": {
                "alt_file": source_path.display().to_string()
            }
        }))
    })
}

pub fn build_outlook(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.Outlook",
        "windows.artemis.outlook",
        is_outlook_store,
    )
}

pub fn collect_outlook(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_outlook_store, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "outlook",
            "outlook": {
                "alt_file": source_path.display().to_string(),
                "include_attachments": false,
                "start_date": null,
                "end_date": null,
                "yara_rule_message": null,
                "yara_rule_attachment": null
            }
        }))
    })
}

pub fn build_shimdb(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    build_root_plan_if_matches(
        root,
        family,
        "Windows.ShimDB",
        "windows.artemis.shimdb",
        is_shimdb_file,
    )
}

pub fn collect_shimdb(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_file_batch(plan, output_dir, is_shimdb_file, |source_path| {
        artifact_from_json(json!({
            "artifact_name": "shimdb",
            "shimdb": {
                "alt_file": source_path.display().to_string()
            }
        }))
    })
}

fn run_artemis_batch(
    plan: &Plan,
    output_dir: &Path,
    runs: Vec<(String, ArtemisArtifacts)>,
) -> Result<(PathBuf, PathBuf)> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create parser output directory {}", output_dir.display()))?;

    let (mut output_file, mut log_file, output_path, log_path) =
        create_output_files(output_dir, &plan.output_name)?;
    let run_root = output_dir.join(format!("{}-artemis", plan.output_name));
    fs::create_dir_all(&run_root)
        .with_context(|| format!("create Artemis staging directory {}", run_root.display()))?;

    let source_count = runs.len();
    let mut total_records = 0usize;

    for (index, (source_label, artifact)) in runs.into_iter().enumerate() {
        let run_name = format!("run-{}", index + 1);
        let (artemis_outputs, artemis_logs) = run_artemis_once(&run_root, &run_name, artifact)?;

        writeln!(log_file, "source={source_label}")?;
        total_records += append_artemis_outputs(
            &mut output_file,
            &mut log_file,
            &artemis_outputs,
            &artemis_logs,
        )?;
    }

    writeln!(log_file, "sources={source_count} records={total_records}")?;
    Ok((output_path, log_path))
}

fn run_artemis_once(
    output_root: &Path,
    run_name: &str,
    artifact: ArtemisArtifacts,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut collection = ArtemisToml {
        output: Output {
            name: run_name.to_string(),
            directory: output_root.display().to_string(),
            format: "jsonl".to_string(),
            compress: false,
            endpoint_id: "holo-forensics".to_string(),
            collection_id: 0,
            output: "local".to_string(),
            timeline: false,
            filter_name: None,
            filter_script: None,
            url: None,
            api_key: None,
            logging: Some("warn".to_string()),
            ..Output::default()
        },
        artifacts: vec![artifact],
        marker: None,
    };

    artemis_collection(&mut collection).context("run Artemis parser")?;

    let artemis_output_dir =
        PathBuf::from(&collection.output.directory).join(&collection.output.name);
    collect_artemis_run_files(&artemis_output_dir)
}

fn collect_artemis_run_files(output_dir: &Path) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut jsonl_files = Vec::new();
    let mut log_files = Vec::new();

    for entry in fs::read_dir(output_dir)
        .with_context(|| format!("read Artemis output directory {}", output_dir.display()))?
    {
        let entry = entry.with_context(|| {
            format!("iterate Artemis output directory {}", output_dir.display())
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let extension = path.extension().and_then(|value| value.to_str());
        match extension {
            Some(value) if value.eq_ignore_ascii_case("jsonl") => jsonl_files.push(path),
            Some(value) if value.eq_ignore_ascii_case("log") => log_files.push(path),
            _ => {}
        }
    }

    jsonl_files.sort();
    log_files.sort();
    Ok((jsonl_files, log_files))
}

fn append_artemis_outputs(
    output_file: &mut File,
    log_file: &mut File,
    artemis_outputs: &[PathBuf],
    artemis_logs: &[PathBuf],
) -> Result<usize> {
    let mut records = 0usize;

    for source_output in artemis_outputs {
        let file = File::open(source_output)
            .with_context(|| format!("open Artemis output {}", source_output.display()))?;
        for line in BufReader::new(file).lines() {
            let line =
                line.with_context(|| format!("read Artemis output {}", source_output.display()))?;
            output_file.write_all(line.as_bytes())?;
            output_file.write_all(b"\n")?;
            records += 1;
        }
        writeln!(log_file, "artemis_output={}", source_output.display())?;
    }

    for artemis_log_path in artemis_logs {
        writeln!(log_file, "artemis_log={}", artemis_log_path.display())?;
        let artemis_log = fs::read_to_string(artemis_log_path)
            .with_context(|| format!("read Artemis log {}", artemis_log_path.display()))?;
        if !artemis_log.is_empty() {
            writeln!(log_file, "{artemis_log}")?;
        }
    }

    Ok(records)
}

fn build_root_plan_if_matches(
    root: &Path,
    family: &ParserFamily,
    artifact: &str,
    collector: &str,
    matcher: fn(&Path) -> bool,
) -> Result<Vec<Plan>> {
    if find_paths(root, matcher)?.is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![new_artemis_root_plan(
        family, root, artifact, collector,
    )])
}

fn new_artemis_root_plan(
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

fn collect_file_batch<F>(
    plan: &Plan,
    output_dir: &Path,
    matcher: fn(&Path) -> bool,
    artifact_builder: F,
) -> Result<(PathBuf, PathBuf)>
where
    F: Fn(&Path) -> Result<ArtemisArtifacts>,
{
    let root = required_root(plan)?;
    let mut runs = Vec::new();
    for source_path in find_paths(&root, matcher)? {
        let artifact = artifact_builder(&source_path)?;
        runs.push((source_path.display().to_string(), artifact));
    }

    run_artemis_batch(plan, output_dir, runs)
}

fn collect_directory_batch<F>(
    plan: &Plan,
    output_dir: &Path,
    matcher: fn(&Path) -> bool,
    artifact_builder: F,
) -> Result<(PathBuf, PathBuf)>
where
    F: Fn(&Path) -> Result<ArtemisArtifacts>,
{
    let root = required_root(plan)?;
    let mut runs = Vec::new();
    for source_path in find_unique_parent_dirs(&root, matcher)? {
        let artifact = artifact_builder(&source_path)?;
        runs.push((source_path.display().to_string(), artifact));
    }

    run_artemis_batch(plan, output_dir, runs)
}

fn find_unique_parent_dirs(root: &Path, matcher: fn(&Path) -> bool) -> Result<Vec<PathBuf>> {
    let mut seen = BTreeSet::new();
    let mut directories = Vec::new();

    for path in find_paths(root, matcher)? {
        let Some(parent) = path.parent() else {
            continue;
        };

        let directory = parent.to_path_buf();
        let key = directory.display().to_string().to_ascii_lowercase();
        if seen.insert(key) {
            directories.push(directory);
        }
    }

    directories.sort();
    Ok(directories)
}

fn artifact_from_json(value: Value) -> Result<ArtemisArtifacts> {
    serde_json::from_value::<ArtemisArtifacts>(value).context("build Artemis configuration")
}

fn jump_lists_artifact(source_path: &Path) -> Result<ArtemisArtifacts> {
    artifact_from_json(json!({
        "artifact_name": "jumplists",
        "jumplists": {
            "alt_dir": source_path.display().to_string()
        }
    }))
}

fn is_prefetch_file(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("pf"))
        .unwrap_or(false)
}

fn is_event_log_file(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("evtx"))
        .unwrap_or(false)
}

fn is_amcache_hive(path: &Path) -> bool {
    file_name_equals(path, "Amcache.hve")
}

fn is_ntuser_hive(path: &Path) -> bool {
    file_name_equals(path, "NTUSER.DAT")
}

fn is_usrclass_hive(path: &Path) -> bool {
    file_name_equals(path, "USRCLASS.DAT")
}

fn is_system_hive(path: &Path) -> bool {
    file_name_equals(path, "SYSTEM")
}

fn is_sam_hive(path: &Path) -> bool {
    file_name_equals(path, "SAM")
}

fn is_shellbags_hive(path: &Path) -> bool {
    is_ntuser_hive(path) || is_usrclass_hive(path)
}

fn is_jump_list_file(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| {
            value.eq_ignore_ascii_case("automaticdestinations-ms")
                || value.eq_ignore_ascii_case("customdestinations-ms")
        })
        .unwrap_or(false)
}

fn is_shortcut_file(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("lnk"))
        .unwrap_or(false)
}

fn is_srum_database(path: &Path) -> bool {
    file_name_equals(path, "SRUDB.dat")
}

fn is_recycle_bin_metadata_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase().starts_with("$i"))
        .unwrap_or(false)
}

fn is_scheduled_task_file(path: &Path) -> bool {
    let normalized = normalize_path(path);
    normalized.contains("/windows/system32/tasks/")
        || (normalized.contains("/windows/tasks/")
            && path
                .extension()
                .and_then(|value| value.to_str())
                .map(|value| value.eq_ignore_ascii_case("job"))
                .unwrap_or(false))
}

fn is_wmi_repository_file(path: &Path) -> bool {
    file_name_equals(path, "OBJECTS.DATA")
}

fn is_mft_file(path: &Path) -> bool {
    file_name_equals(path, "$MFT") || file_name_equals(path, "$MFT.bin")
}

fn is_bits_database(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|value| {
            let normalized = value.to_ascii_lowercase();
            normalized == "qmgr.db" || normalized == "qmgr0.dat" || normalized == "qmgr1.dat"
        })
        .unwrap_or(false)
}

fn is_search_database(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|value| {
            let normalized = value.to_ascii_lowercase();
            normalized == "windows.edb" || normalized == "windows.db"
        })
        .unwrap_or(false)
}

fn is_outlook_store(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("ost") || value.eq_ignore_ascii_case("pst"))
        .unwrap_or(false)
}

fn is_shimdb_file(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("sdb"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;

    use serde_json::json;

    use super::{artifact_from_json, build_mft, build_prefetch, jump_lists_artifact};
    use crate::parser_catalog::ParserFamily;

    #[test]
    fn build_prefetch_creates_one_plan_per_prefetch_directory() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let dir = root.join("C").join("Windows").join("Prefetch");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("APP.EXE-11111111.pf"), b"pf").unwrap();
        fs::write(dir.join("OTHER.EXE-22222222.pf"), b"pf").unwrap();

        let family = ParserFamily {
            name: "windows_prefetch".to_string(),
            collection: "windows_prefetch_collection".to_string(),
            enabled: true,
            ..ParserFamily::default()
        };

        let plans = build_prefetch(root, &family).unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(
            plans[0].local_collector.as_deref(),
            Some("windows.artemis.prefetch")
        );
        assert_eq!(plans[0].artifact, "Windows.Prefetch");
    }

    #[test]
    fn build_mft_detects_collected_mft_bin() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let dir = root.join("C");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("$MFT.bin"), b"mft").unwrap();

        let family = ParserFamily {
            name: "windows_mft".to_string(),
            collection: "windows_mft_collection".to_string(),
            enabled: true,
            ..ParserFamily::default()
        };

        let plans = build_mft(root, &family).unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(
            plans[0].local_collector.as_deref(),
            Some("windows.artemis.mft")
        );
        assert_eq!(plans[0].artifact, "Windows.MFT");
    }

    #[test]
    fn shortcuts_configuration_matches_artemis_schema() {
        let artifact = artifact_from_json(json!({
            "artifact_name": "shortcuts",
            "shortcuts": {
                "dir": r"C:\evidence\Users\juanc\Desktop\*.lnk"
            }
        }));

        assert!(artifact.is_ok());
    }

    #[test]
    fn jumplists_configuration_preserves_alt_dir() {
        let path = Path::new(
            r"C:\evidence\Users\juanc\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\123.automaticDestinations-ms",
        );

        let artifact = jump_lists_artifact(path).unwrap();

        assert_eq!(
            artifact
                .jumplists
                .and_then(|options| options.alt_dir)
                .as_deref(),
            Some(path.to_str().unwrap())
        );
    }

    #[test]
    fn core_windows_artemis_configurations_match_schema() {
        let artifacts = [
            json!({
                "artifact_name": "prefetch",
                "prefetch": {
                    "alt_dir": r"C:\evidence\Windows\Prefetch"
                }
            }),
            json!({
                "artifact_name": "eventlogs",
                "eventlogs": {
                    "alt_file": null,
                    "alt_dir": r"C:\evidence\Windows\System32\winevt\Logs",
                    "include_templates": false,
                    "dump_templates": false,
                    "alt_template_file": null,
                    "only_templates": false
                }
            }),
            json!({
                "artifact_name": "mft",
                "mft": {
                    "alt_file": r"C:\evidence\C\$MFT.bin",
                    "alt_drive": null
                }
            }),
            json!({
                "artifact_name": "bits",
                "bits": {
                    "alt_file": r"C:\evidence\ProgramData\Microsoft\Network\Downloader\qmgr.db",
                    "carve": false
                }
            }),
            json!({
                "artifact_name": "search",
                "search": {
                    "alt_file": r"C:\evidence\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"
                }
            }),
            json!({
                "artifact_name": "outlook",
                "outlook": {
                    "alt_file": r"C:\evidence\Users\juanc\AppData\Local\Microsoft\Outlook\mail.ost",
                    "include_attachments": false,
                    "start_date": null,
                    "end_date": null,
                    "yara_rule_message": null,
                    "yara_rule_attachment": null
                }
            }),
        ];

        for artifact in artifacts {
            assert!(artifact_from_json(artifact).is_ok());
        }
    }
}
