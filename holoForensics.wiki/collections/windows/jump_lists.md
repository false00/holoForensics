# windows_jump_lists_collection

## Summary

Native Rust live collector for Windows Jump List acquisition. The collector uses a VSS snapshot, enumerates per-user Automatic and Custom Jump Lists from the snapshot rather than live paths, preserves original Windows paths in the package, hashes each copied file, and writes a JSONL artifact inventory for downstream review.

## Source

- `src/collections/windows/jump_lists.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`

## Mode

- `vss`: default and only current acquisition mode. Creates or reuses a native Windows VSS snapshot, copies Jump Lists from the point-in-time snapshot, hashes source and destination bytes, and records copy failures honestly.

## CLI

```powershell
holo-forensics collect-jump-lists --volume C: --out-dir C:\temp\jump-lists --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege`.
- Creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when Jump Lists are collected with Registry, EVTX, SRUM, Browser Artifacts, `$MFT`, `$LogFile`, INDX, and/or USN for the same volume.
- Enumerates `C:\Users\*` from the snapshot.
- Skips low-value profiles such as `Default`, `Default User`, `Public`, and `All Users`.
- Skips reparse and symlink paths to avoid recursion loops or collecting redirected content unexpectedly.
- Copies matching files from:
  - `C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms`
  - `C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms`
- Computes a filename-based AppID candidate from each Jump List stem.
- Computes SHA-256 for each VSS source and copied destination file.
- Verifies source and destination hashes match.
- Writes `C/jump_lists_manifest.jsonl` with one JSON object per copied Jump List, including profile username, artifact type, AppID candidate, original path, destination path, timestamps, size, and SHA-256.
- Records file metadata, copied files, warnings, and failures in the centralized manifest.
- Deletes owned VSS snapshots after collection.

## Output

- `C/Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*.automaticDestinations-ms`
- `C/Users/*/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/*.customDestinations-ms`
- `C/jump_lists_manifest.jsonl`
- `$metadata/collectors/C/windows_jump_lists/manifest.json`
- `$metadata/collectors/C/windows_jump_lists/collection.log`

The manifest uses schema `windows_jump_lists_collection_v1` and records source root, source globs, VSS metadata when used, enabled privileges, copied file metadata, SHA-256 values, failures, and warnings.

## Current Scope

- Jump List acquisition is implemented through VSS targeted file copy.
- The collector preserves raw Jump List files for later parser or external-tool analysis; it does not parse OLE or DestList content during collection.
- The JSONL artifact inventory is intended to make preserved Jump Lists easier to review and correlate before a dedicated parser is added.
- Per-user profile discovery is limited to the standard `Users` root on the selected volume.

## Validation

- `cargo test jump_lists`
- `cargo test --locked`
- Desktop Collection tab packages Jump Lists through the same collector path when `Jump Lists` is selected.

## Update Checklist

- Update this page if supported Jump List roots or filename filters change.
- Update this page if profile discovery adds alternate user roots or non-default profile handling.
- Update this page if the JSONL artifact manifest schema or centralized manifest schema changes.