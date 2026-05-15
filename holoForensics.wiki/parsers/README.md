# Parser Index

This index tracks every active parser family shipped by the current Rust runtime and the collection contract each parser expects.

| Family | Collection | Source | Page | Notes |
| --- | --- | --- | --- | --- |
| `linux_shell_history` | `linux_shell_history_collection` | `src/parsers/linux_shell_history.rs` | [linux_shell_history](linux_shell_history.md) | Linux `.bash_history` and `.zsh_history` |
| `macos_browser_history` | `macos_browser_history_collection` | `src/parsers/macos_artifacts.rs` | [macos_browser_history](macos_browser_history.md) | macOS Chrome history |
| `macos_quarantine_events` | `macos_quarantine_events_collection` | `src/parsers/macos_artifacts.rs` | [macos_quarantine_events](macos_quarantine_events.md) | macOS quarantine database |
| `windows_browser_history` | `windows_browser_artifacts_collection` | `src/parsers/windows/browser_history.rs` | [windows/browser_history](windows/browser_history.md) | Windows Chrome, Edge, and Firefox history |
| `windows_event_logs` | `windows_evtx_collection` | `src/parsers/windows/artemis.rs` | [windows/event_logs](windows/event_logs.md) | Windows EVTX event logs via the vendored Artemis adapter |
| `windows_prefetch` | `windows_prefetch_collection` | `src/parsers/windows/artemis.rs` | [windows/prefetch](windows/prefetch.md) | Windows Prefetch `.pf` files via the vendored Artemis adapter |
| `windows_mplogs` | `windows_mplogs_collection` | `src/parsers/windows/mplogs.rs` | [windows/mplogs](windows/mplogs.md) | Microsoft Defender Support `MPLog*.log` text parsing with raw-line preservation |
| `windows_bits` | `windows_bits_collection` | `src/parsers/windows/artemis.rs` | [windows/bits](windows/bits.md) | Windows BITS job databases from supplied evidence packages |
| `windows_search` | `windows_search_collection` | `src/parsers/windows/artemis.rs` | [windows/search](windows/search.md) | Windows Search databases from supplied evidence packages |
| `windows_outlook` | `windows_outlook_collection` | `src/parsers/windows/artemis.rs` | [windows/outlook](windows/outlook.md) | Outlook `.ost` and `.pst` stores from supplied evidence packages |
| `windows_shimdb` | `windows_shimdb_collection` | `src/parsers/windows/artemis.rs` | [windows/shimdb](windows/shimdb.md) | Windows application compatibility `.sdb` databases |
| `windows_userassist` | `windows_registry_collection` | `src/parsers/windows/artemis.rs` | [windows/userassist](windows/userassist.md) | UserAssist data from `NTUSER.DAT` |
| `windows_shimcache` | `windows_registry_collection` | `src/parsers/windows/artemis.rs` | [windows/shimcache](windows/shimcache.md) | ShimCache/AppCompatCache data from `SYSTEM` |
| `windows_shellbags` | `windows_registry_collection` | `src/parsers/windows/artemis.rs` | [windows/shellbags](windows/shellbags.md) | Shellbags from `NTUSER.DAT` and `USRCLASS.DAT` |
| `windows_amcache` | `windows_registry_collection` | `src/parsers/windows/artemis.rs` | [windows/amcache](windows/amcache.md) | `Amcache.hve` execution and install inventory |
| `windows_shortcuts` | `windows_lnk_collection` | `src/parsers/windows/artemis.rs` | [windows/shortcuts](windows/shortcuts.md) | Windows shortcut `.lnk` files |
| `windows_srum` | `windows_srum_collection` | `src/parsers/windows/artemis.rs` | [windows/srum](windows/srum.md) | `SRUDB.dat` SRUM records |
| `windows_users` | `windows_registry_collection` | `src/parsers/windows/artemis.rs` | [windows/users](windows/users.md) | Local user and RID data from `SAM` |
| `windows_services` | `windows_registry_collection` | `src/parsers/windows/artemis.rs` | [windows/services](windows/services.md) | Service configuration data from `SYSTEM` |
| `windows_jump_lists` | `windows_jump_lists_collection` | `src/parsers/windows/artemis.rs` | [windows/jump_lists](windows/jump_lists.md) | AutomaticDestinations and CustomDestinations Jump Lists |
| `windows_recycle_bin` | `windows_recycle_bin_info2_collection` | `src/parsers/windows/artemis.rs` | [windows/recycle_bin](windows/recycle_bin.md) | Modern Recycle Bin `$I*` metadata files |
| `windows_scheduled_tasks` | `windows_scheduled_tasks_collection` | `src/parsers/windows/artemis.rs` | [windows/scheduled_tasks](windows/scheduled_tasks.md) | Legacy `.job` tasks and modern task files |
| `windows_wmi_persistence` | `windows_wmi_repository_collection` | `src/parsers/windows/artemis.rs` | [windows/wmi_persistence](windows/wmi_persistence.md) | WMI persistence data from repository `OBJECTS.DATA` |
| `windows_mft` | `windows_mft_collection` | `src/parsers/windows/artemis.rs` | [windows/mft](windows/mft.md) | Raw NTFS `$MFT` evidence |
| `windows_usn_journal` | `windows_usn_journal_collection` | `src/parsers/windows/usn_journal.rs` | [windows/usn_journal](windows/usn_journal.md) | Raw NTFS `$Extend\$UsnJrnl:$J` stream parsing with manifest/sidecar-aware sparse skipping |
| `windows_registry` | `windows_registry_collection` | `src/parsers/windows/windows_registry.rs` | [windows/windows_registry](windows/windows_registry.md) | Offline Windows Registry hives |
| `windows_restore_point_log` | `windows_restore_point_log_collection` | `src/parsers/windows/restore_point_log.rs` | [windows/restore_point_log](windows/restore_point_log.md) | Restore-point `rp.log` |
| `windows_recycle_bin_info2` | `windows_recycle_bin_info2_collection` | `src/parsers/windows/recycle_bin_info2.rs` | [windows/recycle_bin_info2](windows/recycle_bin_info2.md) | Windows XP `INFO2` |
| `windows_timeline` | `windows_timeline_collection` | `src/parsers/windows/windows_timeline.rs` | [windows/windows_timeline](windows/windows_timeline.md) | Windows Timeline `ActivitiesCache.db` |

## Required Updates

- Add a new page here whenever a new parser family is enabled.
- Remove or rename the matching page when a parser family is removed or renamed.
- Keep the `Collection` column aligned with `src/parser_catalog.rs`.
- Update notes when parser scope, schema, collection binding, or validation status changes.
- Update the affected parser page whenever a major parser behavior, supported input/schema, output fields, collection binding, or validation status changes.
