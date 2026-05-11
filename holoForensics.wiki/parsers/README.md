# Parser Index

This index tracks every active parser family shipped by the current Rust runtime and the collection contract each parser expects.

| Family | Collection | Source | Page | Notes |
| --- | --- | --- | --- | --- |
| `linux_shell_history` | `linux_shell_history_collection` | `src/parsers/linux_shell_history.rs` | [linux_shell_history](linux_shell_history.md) | Linux `.bash_history` and `.zsh_history` |
| `macos_browser_history` | `macos_browser_history_collection` | `src/parsers/macos_artifacts.rs` | [macos_browser_history](macos_browser_history.md) | macOS Chrome history |
| `macos_quarantine_events` | `macos_quarantine_events_collection` | `src/parsers/macos_artifacts.rs` | [macos_quarantine_events](macos_quarantine_events.md) | macOS quarantine database |
| `windows_browser_history` | `windows_browser_artifacts_collection` | `src/parsers/windows/browser_history.rs` | [windows/browser_history](windows/browser_history.md) | Windows Chrome, Edge, and Firefox history |
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
