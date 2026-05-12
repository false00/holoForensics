# windows_powershell_activity_collection

## Summary

Native Rust live collector for Windows PowerShell activity acquisition. The collector uses a VSS snapshot, enumerates eligible user profiles under `Users`, copies fixed PSReadLine history and profile-script targets from the snapshot rather than live paths, selectively copies likely transcript/module/config files under user PowerShell roots, records skipped files with size and reason, and writes centralized collector metadata.

## Source

- `src/collections/windows/powershell_activity.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`

## Mode

- `vss`: default and only current acquisition mode. Creates or reuses a native Windows VSS snapshot, copies PowerShell user artifacts from the point-in-time snapshot, hashes source and destination bytes, and records copy failures honestly.

## CLI

```powershell
holo-forensics collect-powershell-activity --volume C: --out-dir C:\temp\powershell-activity --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege`.
- Creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when PowerShell Activity is collected with Registry, EVTX, SRUM, Prefetch, Scheduled Tasks, Browser Artifacts, Jump Lists, LNK Files, Recycle Bin, `$MFT`, `$LogFile`, INDX, or USN for the same volume.
- Enumerates `Users\<profile>` from the snapshot and skips obvious low-value profile roots such as `Default`, `Default User`, `DefaultAppPool`, `defaultuser0`, `Public`, and `All Users`.
- Copies fixed per-user PowerShell targets when present:
  - `Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
  - `Users\<user>\AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt`
  - `Users\<user>\Documents\WindowsPowerShell\profile.ps1`
  - `Users\<user>\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`
  - `Users\<user>\Documents\WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1`
  - `Users\<user>\Documents\PowerShell\profile.ps1`
  - `Users\<user>\Documents\PowerShell\Microsoft.PowerShell_profile.ps1`
- Enumerates likely transcript files under `Users\<user>\Documents\PowerShell_transcript*.txt`.
- Recursively inventories and selectively copies these user PowerShell roots when present:
  - `Users\<user>\Documents\WindowsPowerShell\Modules\**`
  - `Users\<user>\Documents\PowerShell\Modules\**`
  - `Users\<user>\Documents\WindowsPowerShell\Transcripts\**`
  - `Users\<user>\Documents\PowerShell\Transcripts\**`
  - `Users\<user>\AppData\Local\Microsoft\Windows\PowerShell\**`
  - `Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\**`
  - `Users\<user>\AppData\Local\Microsoft\PowerShell\**`
  - `Users\<user>\AppData\Roaming\Microsoft\PowerShell\**`
- Only copies recursively discovered files when their extension is one of `.ps1`, `.psm1`, `.psd1`, `.ps1xml`, `.clixml`, `.txt`, `.json`, `.xml`, or `.config`.
- Applies a 20 MiB per-file limit to recursive and transcript candidates, and records skipped files with path, size, and reason instead of copying them silently.
- Skips reparse points and symlinks instead of traversing them.
- Preserves raw file bytes by streaming from the VSS source path to the package output.
- Computes SHA-256 for each VSS source stream and copied destination file.
- Verifies source and destination hashes match.
- Records copied file metadata, directory metadata, skipped files, source globs, allowed extensions, maximum file size, shadow-copy metadata, enabled privileges, warnings, and failures in the centralized manifest.
- Deletes owned VSS snapshots after collection.

## Output

- `C/Users/<user>/...` for copied PowerShell activity artifacts
- `$metadata/collectors/C/windows_powershell_activity/manifest.json`
- `$metadata/collectors/C/windows_powershell_activity/collection.log`

The manifest uses schema `windows_powershell_activity_collection_v1` and records profiles scanned and skipped, allowed recursive extensions, the recursive size limit, copied files, directory records, skipped files, failures, warnings, and VSS metadata when used.

## Current Scope

- PowerShell Activity acquisition is implemented through VSS-targeted file copy.
- The collector preserves PSReadLine history, user profile scripts, likely transcripts, and selected script/config/module-support material from user PowerShell roots.
- The collector intentionally skips registry hives and EVTX logs because those are already handled by the dedicated Registry Hives and Windows Event Logs collectors.
- The collector preserves raw evidence for later parser or external-tool analysis; it does not parse scripts, transcripts, registry policy, or event logs during collection.
- Reparse points and symlinks are skipped rather than followed.

## Validation

- `cargo test --locked powershell_activity`
- Desktop Collection tab packages PowerShell Activity through the same collector path when `PowerShell Activity` is selected.

## Update Checklist

- Update this page if the targeted PowerShell roots change.
- Update this page if the recursive extension allowlist or size limit changes.
- Update this page if the manifest schema or centralized archive layout changes.
- Update this page if PowerShell Activity collection expands beyond VSS-backed raw file copy.