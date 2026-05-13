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
        "windows_event_logs" => windows::artemis::build_event_logs(root, family)?,
        "windows_prefetch" => windows::artemis::build_prefetch(root, family)?,
        "windows_bits" => windows::artemis::build_bits(root, family)?,
        "windows_search" => windows::artemis::build_search(root, family)?,
        "windows_outlook" => windows::artemis::build_outlook(root, family)?,
        "windows_shimdb" => windows::artemis::build_shimdb(root, family)?,
        "windows_userassist" => windows::artemis::build_userassist(root, family)?,
        "windows_shimcache" => windows::artemis::build_shimcache(root, family)?,
        "windows_shellbags" => windows::artemis::build_shellbags(root, family)?,
        "windows_amcache" => windows::artemis::build_amcache(root, family)?,
        "windows_shortcuts" => windows::artemis::build_shortcuts(root, family)?,
        "windows_srum" => windows::artemis::build_srum(root, family)?,
        "windows_users" => windows::artemis::build_users(root, family)?,
        "windows_services" => windows::artemis::build_services(root, family)?,
        "windows_jump_lists" => windows::artemis::build_jump_lists(root, family)?,
        "windows_recycle_bin" => windows::artemis::build_recycle_bin(root, family)?,
        "windows_scheduled_tasks" => windows::artemis::build_scheduled_tasks(root, family)?,
        "windows_wmi_persistence" => windows::artemis::build_wmi_persistence(root, family)?,
        "windows_mft" => windows::artemis::build_mft(root, family)?,
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
        Some("windows.artemis.event_logs") => {
            windows::artemis::collect_event_logs(plan, output_dir)
        }
        Some("windows.artemis.prefetch") => windows::artemis::collect_prefetch(plan, output_dir),
        Some("windows.artemis.bits") => windows::artemis::collect_bits(plan, output_dir),
        Some("windows.artemis.search") => windows::artemis::collect_search(plan, output_dir),
        Some("windows.artemis.outlook") => windows::artemis::collect_outlook(plan, output_dir),
        Some("windows.artemis.shimdb") => windows::artemis::collect_shimdb(plan, output_dir),
        Some("windows.artemis.userassist") => {
            windows::artemis::collect_userassist(plan, output_dir)
        }
        Some("windows.artemis.shimcache") => windows::artemis::collect_shimcache(plan, output_dir),
        Some("windows.artemis.shellbags") => windows::artemis::collect_shellbags(plan, output_dir),
        Some("windows.artemis.amcache") => windows::artemis::collect_amcache(plan, output_dir),
        Some("windows.artemis.shortcuts") => windows::artemis::collect_shortcuts(plan, output_dir),
        Some("windows.artemis.srum") => windows::artemis::collect_srum(plan, output_dir),
        Some("windows.artemis.users") => windows::artemis::collect_users(plan, output_dir),
        Some("windows.artemis.services") => windows::artemis::collect_services(plan, output_dir),
        Some("windows.artemis.jump_lists") => {
            windows::artemis::collect_jump_lists(plan, output_dir)
        }
        Some("windows.artemis.recycle_bin") => {
            windows::artemis::collect_recycle_bin(plan, output_dir)
        }
        Some("windows.artemis.scheduled_tasks") => {
            windows::artemis::collect_scheduled_tasks(plan, output_dir)
        }
        Some("windows.artemis.wmi_persistence") => {
            windows::artemis::collect_wmi_persistence(plan, output_dir)
        }
        Some("windows.artemis.mft") => windows::artemis::collect_mft(plan, output_dir),
        Some("windows.usn_journal") => windows::usn_journal::collect(plan, output_dir),
        Some("windows.registry.hive") => windows::windows_registry::collect(plan, output_dir),
        Some("windows.recycle_bin.info2") => windows::recycle_bin_info2::collect(plan, output_dir),
        Some("windows.restore_point.log") => windows::restore_point_log::collect(plan, output_dir),
        Some(name) => Err(anyhow!("local collector {name:?} not registered")),
        None => Err(anyhow!("plan is missing a registered local collector")),
    }
}
