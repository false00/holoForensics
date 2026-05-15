use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};

use crate::collection_catalog;

pub const DEFAULT_PARSE_MODE: &str = "full";

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct ParserFamily {
    pub name: String,
    pub collection: String,
    pub enabled: bool,
    pub args: BTreeMap<String, String>,
    pub per_artifact_args: BTreeMap<String, BTreeMap<String, String>>,
}

pub fn enabled_parser_families() -> Vec<ParserFamily> {
    vec![
        enabled_family(
            "windows_browser_history",
            "windows_browser_artifacts_collection",
        ),
        enabled_family("windows_event_logs", "windows_evtx_collection"),
        enabled_family("windows_prefetch", "windows_prefetch_collection"),
        enabled_family("windows_mplogs", "windows_mplogs_collection"),
        enabled_family("windows_bits", "windows_bits_collection"),
        enabled_family("windows_search", "windows_search_collection"),
        enabled_family("windows_outlook", "windows_outlook_collection"),
        enabled_family("windows_shimdb", "windows_shimdb_collection"),
        enabled_family("windows_userassist", "windows_registry_collection"),
        enabled_family("windows_shimcache", "windows_registry_collection"),
        enabled_family("windows_shellbags", "windows_registry_collection"),
        enabled_family("windows_amcache", "windows_registry_collection"),
        enabled_family("windows_shortcuts", "windows_lnk_collection"),
        enabled_family("windows_srum", "windows_srum_collection"),
        enabled_family("windows_users", "windows_registry_collection"),
        enabled_family("windows_services", "windows_registry_collection"),
        enabled_family("windows_jump_lists", "windows_jump_lists_collection"),
        enabled_family(
            "windows_recycle_bin",
            "windows_recycle_bin_info2_collection",
        ),
        enabled_family(
            "windows_scheduled_tasks",
            "windows_scheduled_tasks_collection",
        ),
        enabled_family(
            "windows_wmi_persistence",
            "windows_wmi_repository_collection",
        ),
        enabled_family("windows_mft", "windows_mft_collection"),
        enabled_family("windows_usn_journal", "windows_usn_journal_collection"),
        enabled_family("windows_registry", "windows_registry_collection"),
        enabled_family(
            "windows_restore_point_log",
            "windows_restore_point_log_collection",
        ),
        enabled_family(
            "windows_recycle_bin_info2",
            "windows_recycle_bin_info2_collection",
        ),
        enabled_family("windows_timeline", "windows_timeline_collection"),
        enabled_family("linux_shell_history", "linux_shell_history_collection"),
        enabled_family("macos_browser_history", "macos_browser_history_collection"),
        enabled_family(
            "macos_quarantine_events",
            "macos_quarantine_events_collection",
        ),
    ]
}

pub fn validate_enabled_parser_families(families: &[ParserFamily]) -> Result<()> {
    collection_catalog::validate_parser_family_collections(families)
}

pub fn find_project_root() -> Result<PathBuf> {
    let working_directory = std::env::current_dir().context("read current working directory")?;
    let candidates = [
        working_directory.clone(),
        working_directory.join("holoForensics"),
    ];
    for candidate in candidates {
        if candidate.join("Cargo.toml").exists() && candidate.join("src").join("main.rs").exists() {
            return Ok(candidate);
        }
    }
    Err(anyhow!(
        "could not find Holo Forensics project root from {}",
        working_directory.display()
    ))
}

fn enabled_family(name: &str, collection: &str) -> ParserFamily {
    ParserFamily {
        name: name.to_string(),
        collection: collection.to_string(),
        enabled: true,
        ..ParserFamily::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{enabled_parser_families, validate_enabled_parser_families};

    #[test]
    fn enabled_parser_families_use_descriptive_names() {
        let families = enabled_parser_families();
        let names = families
            .iter()
            .map(|family| family.name.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "windows_browser_history",
                "windows_event_logs",
                "windows_prefetch",
                "windows_mplogs",
                "windows_bits",
                "windows_search",
                "windows_outlook",
                "windows_shimdb",
                "windows_userassist",
                "windows_shimcache",
                "windows_shellbags",
                "windows_amcache",
                "windows_shortcuts",
                "windows_srum",
                "windows_users",
                "windows_services",
                "windows_jump_lists",
                "windows_recycle_bin",
                "windows_scheduled_tasks",
                "windows_wmi_persistence",
                "windows_mft",
                "windows_usn_journal",
                "windows_registry",
                "windows_restore_point_log",
                "windows_recycle_bin_info2",
                "windows_timeline",
                "linux_shell_history",
                "macos_browser_history",
                "macos_quarantine_events",
            ]
        );

        let collections = families
            .into_iter()
            .map(|family| family.collection)
            .collect::<Vec<_>>();

        assert_eq!(
            collections,
            vec![
                "windows_browser_artifacts_collection",
                "windows_evtx_collection",
                "windows_prefetch_collection",
                "windows_mplogs_collection",
                "windows_bits_collection",
                "windows_search_collection",
                "windows_outlook_collection",
                "windows_shimdb_collection",
                "windows_registry_collection",
                "windows_registry_collection",
                "windows_registry_collection",
                "windows_registry_collection",
                "windows_lnk_collection",
                "windows_srum_collection",
                "windows_registry_collection",
                "windows_registry_collection",
                "windows_jump_lists_collection",
                "windows_recycle_bin_info2_collection",
                "windows_scheduled_tasks_collection",
                "windows_wmi_repository_collection",
                "windows_mft_collection",
                "windows_usn_journal_collection",
                "windows_registry_collection",
                "windows_restore_point_log_collection",
                "windows_recycle_bin_info2_collection",
                "windows_timeline_collection",
                "linux_shell_history_collection",
                "macos_browser_history_collection",
                "macos_quarantine_events_collection",
            ]
        );
    }

    #[test]
    fn enabled_parser_families_reference_registered_collections() {
        let families = enabled_parser_families();
        validate_enabled_parser_families(&families).unwrap();
    }

    #[test]
    fn enabled_parser_families_include_mplogs() {
        let families = enabled_parser_families();

        assert!(families.iter().any(|family| {
            family.name == "windows_mplogs" && family.collection == "windows_mplogs_collection"
        }));
    }
}
