# Windows Parsers

This section mirrors `src/parsers/windows/`.

| Family | Collection | Source | Page | Notes |
| --- | --- | --- | --- | --- |
| `windows_browser_history` | `windows_browser_artifacts_collection` | `src/parsers/windows/browser_history.rs` | [browser_history](browser_history.md) | Windows Chrome, Edge, and Firefox history |
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
