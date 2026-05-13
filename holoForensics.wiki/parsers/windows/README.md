# Windows Parsers

This section mirrors `src/parsers/windows/`.

Most of the families below are routed through the shared adapter in `src/parsers/windows/artemis.rs`, which preserves the existing Holo Forensics plan, manifest, and output layout while invoking the vendored Artemis runtime from `third_party/artemis`. The local fork carries the Windows offline-file fixes used for explicit evidence paths.

| Family | Collection | Source | Page | Notes |
| --- | --- | --- | --- | --- |
| `windows_browser_history` | `windows_browser_artifacts_collection` | `src/parsers/windows/browser_history.rs` | [browser_history](browser_history.md) | Windows Chrome, Edge, and Firefox history |
| `windows_event_logs` | `windows_evtx_collection` | `src/parsers/windows/artemis.rs` | [event_logs](event_logs.md) | Windows EVTX event logs via the vendored Artemis adapter |
| `windows_prefetch` | `windows_prefetch_collection` | `src/parsers/windows/artemis.rs` | [prefetch](prefetch.md) | Windows Prefetch `.pf` files via the vendored Artemis adapter |
| `windows_bits` | `windows_bits_collection` | `src/parsers/windows/artemis.rs` | [bits](bits.md) | Windows BITS job databases from supplied evidence packages |
| `windows_search` | `windows_search_collection` | `src/parsers/windows/artemis.rs` | [search](search.md) | Windows Search databases from supplied evidence packages |
| `windows_outlook` | `windows_outlook_collection` | `src/parsers/windows/artemis.rs` | [outlook](outlook.md) | Outlook `.ost` and `.pst` stores from supplied evidence packages |
| `windows_shimdb` | `windows_shimdb_collection` | `src/parsers/windows/artemis.rs` | [shimdb](shimdb.md) | Windows application compatibility `.sdb` databases |
| `windows_userassist` | `windows_registry_collection` | `src/parsers/windows/artemis.rs` | [userassist](userassist.md) | UserAssist data from `NTUSER.DAT` |
| `windows_shimcache` | `windows_registry_collection` | `src/parsers/windows/artemis.rs` | [shimcache](shimcache.md) | ShimCache/AppCompatCache data from `SYSTEM` |
| `windows_shellbags` | `windows_registry_collection` | `src/parsers/windows/artemis.rs` | [shellbags](shellbags.md) | Shellbags from `NTUSER.DAT` and `USRCLASS.DAT` |
| `windows_amcache` | `windows_registry_collection` | `src/parsers/windows/artemis.rs` | [amcache](amcache.md) | `Amcache.hve` execution and install inventory |
| `windows_shortcuts` | `windows_lnk_collection` | `src/parsers/windows/artemis.rs` | [shortcuts](shortcuts.md) | Windows shortcut `.lnk` files |
| `windows_srum` | `windows_srum_collection` | `src/parsers/windows/artemis.rs` | [srum](srum.md) | `SRUDB.dat` SRUM records |
| `windows_users` | `windows_registry_collection` | `src/parsers/windows/artemis.rs` | [users](users.md) | Local user and RID data from `SAM` |
| `windows_services` | `windows_registry_collection` | `src/parsers/windows/artemis.rs` | [services](services.md) | Service configuration data from `SYSTEM` |
| `windows_jump_lists` | `windows_jump_lists_collection` | `src/parsers/windows/artemis.rs` | [jump_lists](jump_lists.md) | AutomaticDestinations and CustomDestinations Jump Lists |
| `windows_recycle_bin` | `windows_recycle_bin_info2_collection` | `src/parsers/windows/artemis.rs` | [recycle_bin](recycle_bin.md) | Modern Recycle Bin `$I*` metadata files |
| `windows_scheduled_tasks` | `windows_scheduled_tasks_collection` | `src/parsers/windows/artemis.rs` | [scheduled_tasks](scheduled_tasks.md) | Legacy `.job` tasks and modern task files |
| `windows_wmi_persistence` | `windows_wmi_repository_collection` | `src/parsers/windows/artemis.rs` | [wmi_persistence](wmi_persistence.md) | WMI persistence data from repository `OBJECTS.DATA` |
| `windows_mft` | `windows_mft_collection` | `src/parsers/windows/artemis.rs` | [mft](mft.md) | Raw NTFS `$MFT` evidence |
| `windows_usn_journal` | `windows_usn_journal_collection` | `src/parsers/windows/usn_journal.rs` | [usn_journal](usn_journal.md) | Raw NTFS `$Extend\$UsnJrnl:$J` stream parsing with manifest/sidecar-aware sparse skipping |
| `windows_registry` | `windows_registry_collection` | `src/parsers/windows/windows_registry.rs` | [windows_registry](windows_registry.md) | Offline Windows Registry hives |
| `windows_restore_point_log` | `windows_restore_point_log_collection` | `src/parsers/windows/restore_point_log.rs` | [restore_point_log](restore_point_log.md) | Restore-point `rp.log` |
| `windows_recycle_bin_info2` | `windows_recycle_bin_info2_collection` | `src/parsers/windows/recycle_bin_info2.rs` | [recycle_bin_info2](recycle_bin_info2.md) | Windows XP `INFO2` |
| `windows_timeline` | `windows_timeline_collection` | `src/parsers/windows/windows_timeline.rs` | [windows_timeline](windows_timeline.md) | Windows Timeline `ActivitiesCache.db` |

## Required Updates

- Keep this index aligned with `src/parsers/windows/mod.rs` and `src/parser_catalog.rs`.
- Keep the `Collection` column aligned with `src/parser_catalog.rs`.
- Add or remove pages here as the Windows parser set changes.
- Update the affected Windows parser page whenever a major parser behavior, supported input/schema, output fields, collection binding, or validation status changes.
