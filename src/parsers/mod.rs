mod common;
mod linux_shell_history;
mod macos_artifacts;
mod windows;

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

use crate::parser_catalog::ParserFamily;

pub use self::common::Plan;

pub fn build_plans(root: &Path, family: &ParserFamily) -> Result<Option<Vec<Plan>>> {
    let plans = match family.name.as_str() {
        "linux_shell_history" => linux_shell_history::build(root, family)?,
        "macos_browser_history" => macos_artifacts::build_browser_history(root, family)?,
        "macos_quarantine_events" => macos_artifacts::build_quarantine_events(root, family)?,
        "windows_recycle_bin_info2" => windows::recycle_bin_info2::build(root, family)?,
        "windows_usn_journal" => windows::usn_journal::build(root, family)?,
        "windows_registry" => windows::windows_registry::build(root, family)?,
        "windows_restore_point_log" => windows::restore_point_log::build(root, family)?,
        "windows_timeline" => windows::windows_timeline::build(root, family)?,
        "windows_browser_history" => windows::browser_history::build(root, family)?,
        _ => return Ok(None),
    };

    Ok(Some(plans))
}

pub fn collect_local(plan: &Plan, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    match plan.local_collector.as_deref() {
        Some("linux.shell_history") => linux_shell_history::collect_shell_history(plan, output_dir),
        Some("macos.browser_history.chrome") => {
            macos_artifacts::collect_browser_history(plan, output_dir)
        }
        Some("macos.quarantine_events") => {
            macos_artifacts::collect_quarantine_events(plan, output_dir)
        }
        Some("windows.timeline.activities") => windows::windows_timeline::collect(plan, output_dir),
        Some("windows.browser_history.chrome") => {
            windows::browser_history::collect_chrome(plan, output_dir)
        }
        Some("windows.browser_history.edge") => {
            windows::browser_history::collect_edge(plan, output_dir)
        }
        Some("windows.browser_history.firefox") => {
            windows::browser_history::collect_firefox(plan, output_dir)
        }
        Some("windows.usn_journal") => windows::usn_journal::collect(plan, output_dir),
        Some("windows.registry.hive") => windows::windows_registry::collect(plan, output_dir),
        Some("windows.recycle_bin.info2") => windows::recycle_bin_info2::collect(plan, output_dir),
        Some("windows.restore_point.log") => windows::restore_point_log::collect(plan, output_dir),
        Some(name) => Err(anyhow!("local collector {name:?} not registered")),
        None => Err(anyhow!("plan is missing a registered local collector")),
    }
}
