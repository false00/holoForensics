use anyhow::{Result, anyhow};

use crate::parser_catalog::ParserFamily;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionDefinition {
    pub name: &'static str,
    pub platform: &'static str,
    pub artifact: &'static str,
    pub implementation_path: Option<&'static str>,
}

pub fn enabled_collection_definitions() -> Vec<CollectionDefinition> {
    vec![
        collection(
            "linux_shell_history_collection",
            "linux",
            "Linux shell history",
            None,
        ),
        collection(
            "macos_browser_history_collection",
            "macos",
            "macOS browser history",
            None,
        ),
        collection(
            "macos_quarantine_events_collection",
            "macos",
            "macOS quarantine events",
            None,
        ),
        collection(
            "windows_browser_artifacts_collection",
            "windows",
            "Windows Browser Artifacts",
            Some("src/collections/windows/browser_artifacts.rs"),
        ),
        collection(
            "windows_jump_lists_collection",
            "windows",
            "Windows Jump Lists",
            Some("src/collections/windows/jump_lists.rs"),
        ),
        collection(
            "windows_evtx_collection",
            "windows",
            "Windows Event Logs",
            Some("src/collections/windows/evtx.rs"),
        ),
        collection(
            "windows_registry_collection",
            "windows",
            "Windows Registry hives",
            Some("src/collections/windows/registry.rs"),
        ),
        collection(
            "windows_mft_collection",
            "windows",
            "Windows Master File Table",
            Some("src/collections/windows/mft.rs"),
        ),
        collection(
            "windows_logfile_collection",
            "windows",
            "Windows NTFS $LogFile",
            Some("src/collections/windows/logfile.rs"),
        ),
        collection(
            "windows_indx_collection",
            "windows",
            "Windows NTFS INDX directory indexes",
            Some("src/collections/windows/indx.rs"),
        ),
        collection(
            "windows_srum_collection",
            "windows",
            "Windows SRUM",
            Some("src/collections/windows/srum.rs"),
        ),
        collection(
            "windows_restore_point_log_collection",
            "windows",
            "Windows restore point logs",
            None,
        ),
        collection(
            "windows_recycle_bin_info2_collection",
            "windows",
            "Windows XP recycle bin INFO2",
            None,
        ),
        collection(
            "windows_timeline_collection",
            "windows",
            "Windows Timeline",
            None,
        ),
        collection(
            "windows_usn_journal_collection",
            "windows",
            "Windows USN Journal",
            Some("src/collections/windows/usn_journal.rs"),
        ),
    ]
}

pub fn is_registered_collection(name: &str) -> bool {
    enabled_collection_definitions()
        .iter()
        .any(|definition| definition.name == name)
}

pub fn validate_parser_family_collections(families: &[ParserFamily]) -> Result<()> {
    for family in families {
        if family.collection.trim().is_empty() {
            return Err(anyhow!(
                "parser family {} is missing a collection binding",
                family.name
            ));
        }
        if !is_registered_collection(&family.collection) {
            return Err(anyhow!(
                "parser family {} references unregistered collection {}",
                family.name,
                family.collection
            ));
        }
    }

    Ok(())
}

fn collection(
    name: &'static str,
    platform: &'static str,
    artifact: &'static str,
    implementation_path: Option<&'static str>,
) -> CollectionDefinition {
    CollectionDefinition {
        name,
        platform,
        artifact,
        implementation_path,
    }
}

#[cfg(test)]
mod tests {
    use super::enabled_collection_definitions;

    #[test]
    fn enabled_collections_include_usn_journal_definition() {
        let collections = enabled_collection_definitions();
        assert!(collections.iter().any(|definition| {
            definition.name == "windows_usn_journal_collection"
                && definition.implementation_path == Some("src/collections/windows/usn_journal.rs")
        }));
    }

    #[test]
    fn enabled_collections_include_registry_definition() {
        let collections = enabled_collection_definitions();
        assert!(collections.iter().any(|definition| {
            definition.name == "windows_registry_collection"
                && definition.implementation_path == Some("src/collections/windows/registry.rs")
        }));
    }

    #[test]
    fn enabled_collections_include_evtx_definition() {
        let collections = enabled_collection_definitions();
        assert!(collections.iter().any(|definition| {
            definition.name == "windows_evtx_collection"
                && definition.implementation_path == Some("src/collections/windows/evtx.rs")
        }));
    }

    #[test]
    fn enabled_collections_include_mft_definition() {
        let collections = enabled_collection_definitions();
        assert!(collections.iter().any(|definition| {
            definition.name == "windows_mft_collection"
                && definition.implementation_path == Some("src/collections/windows/mft.rs")
        }));
    }

    #[test]
    fn enabled_collections_include_logfile_definition() {
        let collections = enabled_collection_definitions();
        assert!(collections.iter().any(|definition| {
            definition.name == "windows_logfile_collection"
                && definition.implementation_path == Some("src/collections/windows/logfile.rs")
        }));
    }

    #[test]
    fn enabled_collections_include_indx_definition() {
        let collections = enabled_collection_definitions();
        assert!(collections.iter().any(|definition| {
            definition.name == "windows_indx_collection"
                && definition.implementation_path == Some("src/collections/windows/indx.rs")
        }));
    }

    #[test]
    fn enabled_collections_include_srum_definition() {
        let collections = enabled_collection_definitions();
        assert!(collections.iter().any(|definition| {
            definition.name == "windows_srum_collection"
                && definition.implementation_path == Some("src/collections/windows/srum.rs")
        }));
    }

    #[test]
    fn enabled_collections_include_browser_artifacts_definition() {
        let collections = enabled_collection_definitions();
        assert!(collections.iter().any(|definition| {
            definition.name == "windows_browser_artifacts_collection"
                && definition.implementation_path
                    == Some("src/collections/windows/browser_artifacts.rs")
        }));
    }

    #[test]
    fn enabled_collections_include_jump_lists_definition() {
        let collections = enabled_collection_definitions();
        assert!(collections.iter().any(|definition| {
            definition.name == "windows_jump_lists_collection"
                && definition.implementation_path == Some("src/collections/windows/jump_lists.rs")
        }));
    }
}
