# windows_wmi_repository_collection

## Summary

Native Rust live collector for Windows WMI repository acquisition. The collector uses a VSS snapshot, copies WMI repository trees and supporting WBEM recovery material from the snapshot rather than the live path, streams bytes while hashing, records file and directory metadata, and writes centralized collector metadata.

## Source

- `src/collections/windows/wmi_repository.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`

## Mode

- `vss`: default and only current acquisition mode. Creates or reuses a native Windows VSS snapshot, copies WMI repository artifacts from the point-in-time snapshot, hashes source and destination bytes, and records copy failures honestly.

## CLI

```powershell
holo-forensics collect-wmi-repository --volume C: --out-dir C:\temp\wmi-repository --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege`.
- Creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when WMI Repository is collected with Registry, EVTX, SRUM, Prefetch, Scheduled Tasks, PowerShell Activity, Browser Artifacts, Jump Lists, LNK Files, Recycle Bin, `$MFT`, `$LogFile`, INDX, or USN for the same volume.
- Enumerates the following WMI repository roots from the snapshot:
  - `C:\Windows\System32\wbem\Repository*\**`
  - `C:\Windows\System32\wbem\AutoRecover\**`
  - `C:\Windows\System32\wbem\*.mof`
  - `C:\Windows\System32\wbem\*.mfl`
- Treats any top-level WBEM directory whose name starts with `Repository` as in-scope so numbered repository copies and nested FS content are preserved rather than curated away.
- Skips reparse points and symlinks instead of traversing them.
- Preserves raw file bytes by streaming from the VSS source path to the package output.
- Computes SHA-256 for each VSS source stream and copied destination file.
- Verifies source and destination hashes match.
- Records copied file metadata, directory metadata, source globs, shadow-copy metadata, enabled privileges, warnings, and failures in the centralized manifest.
- Deletes owned VSS snapshots after collection.

## Output

- `C/Windows/System32/wbem/Repository*/**/*`
- `C/Windows/System32/wbem/AutoRecover/**/*`
- `C/Windows/System32/wbem/*.mof`
- `C/Windows/System32/wbem/*.mfl`
- `$metadata/collectors/C/windows_wmi_repository/manifest.json`
- `$metadata/collectors/C/windows_wmi_repository/collection.log`

The manifest uses schema `windows_wmi_repository_collection_v1` and records source globs, VSS metadata when used, enabled privileges, copied file metadata, directory metadata, SHA-256 values, failures, and warnings.

## Current Scope

- WMI Repository acquisition is implemented through VSS-targeted file copy.
- The collector preserves Repository* trees recursively, AutoRecover content, and top-level WBEM MOF and MFL files that often support repository reconstruction and persistence analysis.
- The collector intentionally skips registry hives and EVTX logs because those are already handled by the dedicated Registry Hives and Windows Event Logs collectors.
- The collector preserves raw evidence for later parser or external-tool analysis; it does not parse WMI objects, repository pages, registry state, or event logs during collection.
- Reparse points and symlinks are skipped rather than followed.

## Validation

- `cargo test --locked wmi_repository`
- Desktop Collection tab packages WMI Repository through the same collector path when `WMI Repository` is selected.

## Update Checklist

- Update this page if the targeted WBEM roots change.
- Update this page if the manifest schema or centralized archive layout changes.
- Update this page if WMI Repository collection expands beyond VSS-backed raw file copy.