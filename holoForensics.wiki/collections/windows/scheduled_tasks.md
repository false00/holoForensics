# windows_scheduled_tasks_collection

## Summary

Native Rust live collector for Windows Scheduled Tasks acquisition. The collector uses a VSS snapshot, copies legacy and modern scheduled task artifacts from the snapshot rather than the live path, streams bytes while hashing, records source timestamps and attributes for both files and task directories, and writes centralized collector metadata.

## Source

- `src/collections/windows/scheduled_tasks.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`

## Mode

- `vss`: default and only current acquisition mode. Creates or reuses a native Windows VSS snapshot, copies scheduled task artifacts from the point-in-time snapshot, hashes source and destination bytes, and records copy failures honestly.

## CLI

```powershell
holo-forensics collect-scheduled-tasks --volume C: --out-dir C:\temp\scheduled-tasks --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege`.
- Creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when Scheduled Tasks is collected with Registry, EVTX, SRUM, Prefetch, Browser Artifacts, Jump Lists, LNK Files, Recycle Bin, `$MFT`, `$LogFile`, INDX, or USN for the same volume.
- Enumerates the following scheduled task roots from the snapshot:
  - `C:\Windows\Tasks\**`
  - `C:\Windows\SchedLgU.txt`
  - `C:\Windows\System32\Tasks\**`
- Skips reparse points and symlinks instead of traversing them.
- Preserves raw file bytes by streaming from the VSS source path to the package output.
- Computes SHA-256 for each VSS source stream and copied destination file.
- Verifies source and destination hashes match.
- Records file metadata and directory metadata, including timestamps and Windows file attributes, in the centralized manifest.
- Records shadow-copy ID, device object, source globs, enabled privileges, warnings, and failures in the centralized manifest.
- Deletes owned VSS snapshots after collection.

## Output

- `C/Windows/Tasks/**/*`
- `C/Windows/SchedLgU.txt`
- `C/Windows/System32/Tasks/**/*`
- `$metadata/collectors/C/windows_scheduled_tasks/manifest.json`
- `$metadata/collectors/C/windows_scheduled_tasks/collection.log`

The manifest uses schema `windows_scheduled_tasks_collection_v1` and records source globs, VSS metadata when used, enabled privileges, copied file metadata, directory metadata, SHA-256 values, failures, and warnings.

## Current Scope

- Scheduled Tasks acquisition is implemented through VSS-targeted file copy.
- The collector records legacy task job files, the legacy `SchedLgU.txt` scheduler log when present, and modern task definition files under `System32\Tasks`.
- The collector preserves raw evidence for later parser or external-tool analysis; it does not parse task XML, registry data, or Task Scheduler event logs during collection.
- Reparse points and symlinks are skipped rather than followed.

## Validation

- `cargo test --locked scheduled_tasks`
- `cargo test --locked`
- Desktop Collection tab packages Scheduled Tasks through the same collector path when `Scheduled Tasks` is selected.

## Update Checklist

- Update this page if the targeted Scheduled Tasks roots change.
- Update this page if the manifest schema or centralized archive layout changes.
- Update this page if Scheduled Tasks collection expands beyond VSS-backed raw file copy.
