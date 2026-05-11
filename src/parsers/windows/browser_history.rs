use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{Map, Value};

use crate::parser_catalog::ParserFamily;
use crate::parsers::common::{
    Plan, chrome_time_to_rfc3339_from_i64, chromium_visit_source, create_output_files, find_paths,
    has_matches, is_chrome_history, is_edge_history, is_firefox_history, new_local_plan,
    open_sqlite, required_root, unix_microseconds_to_rfc3339, windows_user_from_path,
    write_json_line,
};

pub fn build(root: &Path, family: &ParserFamily) -> Result<Vec<Plan>> {
    let mut plans = Vec::new();

    if has_matches(root, is_chrome_history)? {
        plans.push(new_local_plan(
            family,
            root,
            "Windows.Applications.Chrome.History",
            "windows.browser_history.chrome",
        ));
    }

    if has_matches(root, is_edge_history)? {
        plans.push(new_local_plan(
            family,
            root,
            "Windows.Applications.Edge.History",
            "windows.browser_history.edge",
        ));
    }

    if has_matches(root, is_firefox_history)? {
        plans.push(new_local_plan(
            family,
            root,
            "Windows.Applications.Firefox.History",
            "windows.browser_history.firefox",
        ));
    }

    Ok(plans)
}

pub fn collect_chrome(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_chromium(plan, output_dir, "chrome", is_chrome_history)
}

pub fn collect_edge(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    collect_chromium(plan, output_dir, "edge", is_edge_history)
}

pub fn collect_firefox(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let root = required_root(plan)?;
    let paths = find_paths(&root, is_firefox_history)?;
    let (mut output_file, mut log_file, output_path, log_path) =
        create_output_files(output_dir, &plan.output_name)?;

    let mut records = 0usize;
    for path in &paths {
        match collect_firefox_file(&mut output_file, path) {
            Ok(written) => records += written,
            Err(error) => writeln!(log_file, "skip {}: {error}", path.display())?,
        }
    }

    writeln!(log_file, "files={} records={records}", paths.len())?;
    Ok((output_path, log_path))
}

fn collect_chromium(
    plan: &Plan,
    output_dir: &Path,
    browser: &str,
    matcher: fn(&Path) -> bool,
) -> Result<(PathBuf, PathBuf)> {
    let root = required_root(plan)?;
    let paths = find_paths(&root, matcher)?;
    let (mut output_file, mut log_file, output_path, log_path) =
        create_output_files(output_dir, &plan.output_name)?;

    let mut records = 0usize;
    for path in &paths {
        match collect_chromium_file(&mut output_file, path, browser) {
            Ok(written) => records += written,
            Err(error) => writeln!(log_file, "skip {}: {error}", path.display())?,
        }
    }

    writeln!(log_file, "files={} records={records}", paths.len())?;
    Ok((output_path, log_path))
}

fn collect_chromium_file(output_file: &mut File, path: &Path, browser: &str) -> Result<usize> {
    let connection = open_sqlite(path)?;
    let mut statement = connection.prepare("SELECT U.id, U.url, V.visit_time, U.title, U.visit_count, U.typed_count, U.last_visit_time, U.hidden, COALESCE(VS.source, 1), V.from_visit, V.visit_duration, V.transition FROM urls AS U JOIN visits AS V ON U.id = V.url LEFT JOIN visit_source AS VS ON V.id = VS.id")?;
    let mut rows = statement.query([])?;
    let user = windows_user_from_path(path);
    let mut records = 0usize;

    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let visited_url: String = row.get(1)?;
        let visit_time: i64 = row.get(2)?;
        let title: Option<String> = row.get(3)?;
        let visit_count: Option<i64> = row.get(4)?;
        let typed_count: Option<i64> = row.get(5)?;
        let last_visit_time: Option<i64> = row.get(6)?;
        let hidden: Option<i64> = row.get(7)?;
        let source: Option<i64> = row.get(8)?;
        let from_visit: Option<i64> = row.get(9)?;
        let visit_duration: Option<i64> = row.get(10)?;
        let transition: Option<i64> = row.get(11)?;

        let mut record = Map::new();
        record.insert("browser".to_string(), Value::String(browser.to_string()));
        record.insert("user".to_string(), Value::String(user.clone()));
        record.insert("url_id".to_string(), Value::from(id));
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
            "hidden".to_string(),
            Value::Bool(hidden.unwrap_or_default() != 0),
        );
        record.insert(
            "from_url_id".to_string(),
            Value::from(from_visit.unwrap_or_default()),
        );
        record.insert(
            "source".to_string(),
            Value::String(chromium_visit_source(source.unwrap_or(1)).to_string()),
        );
        record.insert(
            "visit_duration_microseconds".to_string(),
            Value::from(visit_duration.unwrap_or_default()),
        );
        record.insert(
            "transition".to_string(),
            Value::from(transition.unwrap_or_default()),
        );
        record.insert(
            "os_path".to_string(),
            Value::String(path.display().to_string()),
        );
        if let Some(value) = chrome_time_to_rfc3339_from_i64(visit_time) {
            record.insert("visit_time".to_string(), Value::String(value));
        }
        if let Some(value) = last_visit_time.and_then(chrome_time_to_rfc3339_from_i64) {
            record.insert("last_visit_time".to_string(), Value::String(value));
        }

        write_json_line(output_file, &record)?;
        records += 1;
    }

    Ok(records)
}

fn collect_firefox_file(output_file: &mut File, path: &Path) -> Result<usize> {
    let connection = open_sqlite(path)?;
    let mut statement = connection.prepare("SELECT H.id, H.from_visit, H.visit_date, P.url, P.title, P.rev_host, P.visit_count, P.hidden, P.typed, P.description FROM moz_historyvisits AS H JOIN moz_places AS P ON H.place_id = P.id")?;
    let mut rows = statement.query([])?;
    let user = windows_user_from_path(path);
    let mut records = 0usize;

    while let Some(row) = rows.next()? {
        let visit_id: i64 = row.get(0)?;
        let from_visit: Option<i64> = row.get(1)?;
        let visit_date: Option<i64> = row.get(2)?;
        let visited_url: String = row.get(3)?;
        let title: Option<String> = row.get(4)?;
        let rev_host: Option<String> = row.get(5)?;
        let visit_count: Option<i64> = row.get(6)?;
        let hidden: Option<i64> = row.get(7)?;
        let typed: Option<i64> = row.get(8)?;
        let description: Option<String> = row.get(9)?;

        let mut record = Map::new();
        record.insert("browser".to_string(), Value::String("firefox".to_string()));
        record.insert("user".to_string(), Value::String(user.clone()));
        record.insert("visit_id".to_string(), Value::from(visit_id));
        record.insert(
            "from_visit".to_string(),
            Value::from(from_visit.unwrap_or_default()),
        );
        record.insert("visited_url".to_string(), Value::String(visited_url));
        record.insert(
            "title".to_string(),
            Value::String(title.unwrap_or_default()),
        );
        record.insert(
            "rev_host".to_string(),
            Value::String(rev_host.unwrap_or_default()),
        );
        record.insert(
            "visit_count".to_string(),
            Value::from(visit_count.unwrap_or_default()),
        );
        record.insert(
            "hidden".to_string(),
            Value::Bool(hidden.unwrap_or_default() != 0),
        );
        record.insert(
            "typed".to_string(),
            Value::Bool(typed.unwrap_or_default() != 0),
        );
        record.insert(
            "description".to_string(),
            Value::String(description.unwrap_or_default()),
        );
        record.insert(
            "os_path".to_string(),
            Value::String(path.display().to_string()),
        );
        if let Some(visit_time) = visit_date.and_then(unix_microseconds_to_rfc3339) {
            record.insert("visit_time".to_string(), Value::String(visit_time));
        }

        write_json_line(output_file, &record)?;
        records += 1;
    }

    Ok(records)
}
