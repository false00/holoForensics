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
pub const WINDOWS_PREFETCH_COLLECTOR: &str = "windows_prefetch";
pub const WINDOWS_MPLOGS_COLLECTOR: &str = "windows_mplogs";
pub const WINDOWS_POWERSHELL_ACTIVITY_COLLECTOR: &str = "windows_powershell_activity";
pub const WINDOWS_BROWSER_ARTIFACTS_COLLECTOR: &str = "windows_browser_artifacts";
pub const WINDOWS_JUMP_LISTS_COLLECTOR: &str = "windows_jump_lists";
pub const WINDOWS_LNK_COLLECTOR: &str = "windows_lnk";
pub const WINDOWS_RECYCLE_BIN_COLLECTOR: &str = "windows_recycle_bin";
pub const WINDOWS_SCHEDULED_TASKS_COLLECTOR: &str = "windows_scheduled_tasks";
pub const WINDOWS_WMI_REPOSITORY_COLLECTOR: &str = "windows_wmi_repository";

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
        WINDOWS_JUMP_LISTS_COLLECTOR, WINDOWS_LNK_COLLECTOR, WINDOWS_LOGFILE_COLLECTOR,
        WINDOWS_MFT_COLLECTOR, WINDOWS_MPLOGS_COLLECTOR, WINDOWS_POWERSHELL_ACTIVITY_COLLECTOR,
        WINDOWS_PREFETCH_COLLECTOR, WINDOWS_RECYCLE_BIN_COLLECTOR, WINDOWS_REGISTRY_COLLECTOR,
        WINDOWS_SCHEDULED_TASKS_COLLECTOR, WINDOWS_SRUM_COLLECTOR,
        WINDOWS_WMI_REPOSITORY_COLLECTOR, collector_log_archive_path,
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
            collector_manifest_archive_path("c:", WINDOWS_PREFETCH_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_prefetch")
                .join("manifest.json")
        );
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_MPLOGS_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_mplogs")
                .join("manifest.json")
        );
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_POWERSHELL_ACTIVITY_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_powershell_activity")
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
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_LNK_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_lnk")
                .join("manifest.json")
        );
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_RECYCLE_BIN_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_recycle_bin")
                .join("manifest.json")
        );
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_SCHEDULED_TASKS_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_scheduled_tasks")
                .join("manifest.json")
        );
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_WMI_REPOSITORY_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_wmi_repository")
                .join("manifest.json")
        );
        Ok(())
    }

    #[test]
    fn prefetch_collector_manifest_path_uses_central_archive_root() -> Result<()> {
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_PREFETCH_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_prefetch")
                .join("manifest.json")
        );
        Ok(())
    }

    #[test]
    fn mplogs_collector_manifest_path_uses_central_archive_root() -> Result<()> {
        assert_eq!(
            collector_manifest_archive_path("c:", WINDOWS_MPLOGS_COLLECTOR)?,
            PathBuf::from("$metadata")
                .join("collectors")
                .join("C")
                .join("windows_mplogs")
                .join("manifest.json")
        );
        Ok(())
    }
}
