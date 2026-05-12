use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

pub const METADATA_ROOT: &str = "$metadata";
pub const COLLECTORS_ROOT: &str = "collectors";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const COLLECTION_LOG_FILE: &str = "collection.log";
pub const WINDOWS_REGISTRY_COLLECTOR: &str = "windows_registry";
pub const WINDOWS_USN_JOURNAL_COLLECTOR: &str = "windows_usn_journal";
pub const WINDOWS_EVTX_COLLECTOR: &str = "windows_evtx";
pub const WINDOWS_MFT_COLLECTOR: &str = "windows_mft";
pub const WINDOWS_LOGFILE_COLLECTOR: &str = "windows_logfile";
pub const WINDOWS_INDX_COLLECTOR: &str = "windows_indx";
pub const WINDOWS_SRUM_COLLECTOR: &str = "windows_srum";
pub const WINDOWS_BROWSER_ARTIFACTS_COLLECTOR: &str = "windows_browser_artifacts";
pub const WINDOWS_JUMP_LISTS_COLLECTOR: &str = "windows_jump_lists";

pub fn collector_metadata_archive_dir(volume: &str, collector: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(METADATA_ROOT)
        .join(COLLECTORS_ROOT)
        .join(volume_label(volume)?)
        .join(collector))
}

pub fn collector_manifest_archive_path(volume: &str, collector: &str) -> Result<PathBuf> {
    Ok(collector_metadata_archive_dir(volume, collector)?.join(MANIFEST_FILE))
}

pub fn collector_log_archive_path(volume: &str, collector: &str) -> Result<PathBuf> {
    Ok(collector_metadata_archive_dir(volume, collector)?.join(COLLECTION_LOG_FILE))
}

pub fn collector_manifest_path(
    output_root: &Path,
    volume: &str,
    collector: &str,
) -> Result<PathBuf> {
    Ok(output_root.join(collector_manifest_archive_path(volume, collector)?))
}

pub fn collector_log_path(output_root: &Path, volume: &str, collector: &str) -> Result<PathBuf> {
    Ok(output_root.join(collector_log_archive_path(volume, collector)?))
}

pub fn volume_label(volume: &str) -> Result<String> {
    let trimmed = volume.trim().trim_start_matches(r"\\?\");
    let label = trimmed.trim_end_matches(':');
    if label.len() == 1 && label.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return Ok(label.to_ascii_uppercase());
    }
    bail!("unsupported collection metadata volume label: {volume}");
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Result;

    use super::{
        WINDOWS_BROWSER_ARTIFACTS_COLLECTOR, WINDOWS_EVTX_COLLECTOR, WINDOWS_INDX_COLLECTOR,
        WINDOWS_JUMP_LISTS_COLLECTOR, WINDOWS_LOGFILE_COLLECTOR, WINDOWS_MFT_COLLECTOR,
        WINDOWS_REGISTRY_COLLECTOR, WINDOWS_SRUM_COLLECTOR, collector_log_archive_path,
        collector_manifest_archive_path,
    };

    #[test]
    fn collector_metadata_paths_live_under_central_archive_root() -> Result<()> {
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_REGISTRY_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_registry")
                .join("manifest.json")
        );
        assert_eq!(
            collector_log_archive_path(r"\\?\C:", WINDOWS_REGISTRY_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_registry")
                .join("collection.log")
        );
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_EVTX_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_evtx")
                .join("manifest.json")
        );
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_MFT_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_mft")
                .join("manifest.json")
        );
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_LOGFILE_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_logfile")
                .join("manifest.json")
        );
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_INDX_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_indx")
                .join("manifest.json")
        );
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_SRUM_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_srum")
                .join("manifest.json")
        );
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_BROWSER_ARTIFACTS_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_browser_artifacts")
                .join("manifest.json")
        );
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_JUMP_LISTS_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_jump_lists")
                .join("manifest.json")
        );
        Ok(())
    }
}
