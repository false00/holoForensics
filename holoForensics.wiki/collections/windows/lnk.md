# windows_lnk_collection

## Summary

Native Rust live collector for Windows shortcut acquisition. The collector uses a VSS snapshot, enumerates targeted LNK roots from the snapshot rather than live paths, preserves raw `.lnk` bytes without shell resolution, hashes each copied file, and writes a JSONL artifact inventory for downstream review.

This contract now feeds the `windows_shortcuts` parser family through the shared Artemis adapter in `src/parsers/windows/artemis.rs`.

## Source

- `src/collections/windows/lnk.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`
- Desktop selection surface: `src/desktop.rs`

## Mode

- `vss`: default and only current acquisition mode. Creates or reuses a native Windows VSS snapshot, copies raw LNK files from the point-in-time snapshot, hashes source and destination bytes, and records copy failures honestly.

## CLI

```powershell
holo-forensics collect-lnk --volume C: --out-dir C:\temp\lnk --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege`.
- Creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell, Explorer, Shell, or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when LNK Files are collected with Registry, EVTX, SRUM, Prefetch, Browser Artifacts, Jump Lists, `$MFT`, `$LogFile`, INDX, and/or USN for the same volume.
- Enumerates `C:\Users\*` from the snapshot.
- Skips low-value profiles such as `Default`, `Default User`, `Public`, and `All Users`.
- Skips reparse and symlink paths to avoid recursion loops or collecting redirected content unexpectedly.
- Copies matching files from:
  - `C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk`
  - `C:\Users\*\AppData\Roaming\Microsoft\Office\Recent\*.lnk`
  - `C:\Users\*\Desktop\*.lnk`
  - `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\**\*.lnk`
  - `C:\ProgramData\Microsoft\Windows\Start Menu\**\*.lnk`
- Copies raw `.lnk` bytes only. It does not open the shortcut, resolve the target, or allow Windows Explorer or Shell interpretation during acquisition.
- Computes SHA-256 for each VSS source and copied destination file.
- Verifies source and destination hashes match.
- Writes `C/lnk_manifest.jsonl` with one JSON object per copied LNK, including profile username when present, logical location, original path, destination path, timestamps, size, file attributes, and SHA-256.
- Records file metadata, copied files, warnings, and failures in the centralized manifest.
- Deletes owned VSS snapshots after collection.

## Output

- `C/Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk`
- `C/Users/*/AppData/Roaming/Microsoft/Office/Recent/*.lnk`
- `C/Users/*/Desktop/*.lnk`
- `C/Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/**/*.lnk`
- `C/ProgramData/Microsoft/Windows/Start Menu/**/*.lnk`
- `C/lnk_manifest.jsonl`
- `$metadata/collectors/C/windows_lnk/manifest.json`
- `$metadata/collectors/C/windows_lnk/collection.log`

The manifest uses schema `windows_lnk_collection_v1` and records source roots, location labels, VSS metadata when used, enabled privileges, copied file metadata, timestamps, file attributes, SHA-256 values, failures, and warnings.

## Current Scope

- LNK acquisition is implemented through VSS-targeted file copy.
- The collector preserves raw shortcut files for later parser or external-tool analysis; it does not resolve or parse shell-link internals during collection.
- The JSONL artifact inventory is intended to make preserved shortcuts easier to review and correlate before a dedicated parser is added.
- Per-user profile discovery is limited to the standard `Users` root on the selected volume.

## Validation

- `cargo test lnk`
- `cargo test --locked`
- Desktop Collection tab packages LNK Files through the same collector path when `LNK Files` is selected.

## Update Checklist

- Update this page if supported LNK roots or filename filters change.
- Update this page if profile discovery adds alternate user roots or non-default profile handling.
- Update this page if the JSONL artifact manifest schema or centralized manifest schema changes.