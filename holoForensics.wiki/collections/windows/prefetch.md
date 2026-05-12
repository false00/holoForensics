# windows_prefetch_collection

## Summary

Native Rust live collector for Windows Prefetch acquisition. The collector uses a VSS snapshot, copies targeted Prefetch artifacts from the snapshot rather than the live path, streams bytes while hashing, and records source timestamps, file attributes, and shadow-copy metadata in the centralized manifest.

## Source

- `src/collections/windows/prefetch.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`

## Mode

- `vss`: default and only current acquisition mode. Creates or reuses a native Windows VSS snapshot, copies Prefetch artifacts from the point-in-time snapshot, hashes source and destination bytes, and records copy failures honestly.

## CLI

```powershell
holo-forensics collect-prefetch --volume C: --out-dir C:\temp\prefetch --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege`.
- Creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when Prefetch is collected with Registry, EVTX, SRUM, Browser Artifacts, Jump Lists, `$MFT`, `$LogFile`, INDX, and/or USN for the same volume.
- Enumerates `C:\Windows\Prefetch` from the snapshot.
- Copies only targeted evidence files from the snapshot root:
  - `C:\Windows\Prefetch\*.pf`
  - `C:\Windows\Prefetch\Layout.ini`
  - `C:\Windows\Prefetch\Ag*.db`
- Preserves raw file bytes by streaming from the VSS source path to the package output.
- Computes SHA-256 for each VSS source stream and copied destination file.
- Verifies source and destination hashes match.
- Records file metadata, including timestamps and Windows file attributes, in the centralized manifest.
- Records shadow-copy ID, device object, source globs, enabled privileges, warnings, and failures in the centralized manifest.
- Deletes owned VSS snapshots after collection.

## Output

- `C/Windows/Prefetch/*.pf`
- `C/Windows/Prefetch/Layout.ini`
- `C/Windows/Prefetch/Ag*.db`
- `$metadata/collectors/C/windows_prefetch/manifest.json`
- `$metadata/collectors/C/windows_prefetch/collection.log`

The manifest uses schema `windows_prefetch_collection_v1` and records source root, source globs, VSS metadata when used, enabled privileges, copied file metadata, timestamps, file attributes, SHA-256 values, failures, and warnings.

## Current Scope

- Prefetch acquisition is implemented through VSS-targeted file copy.
- The collector records application Prefetch files, the boot Prefetch file when present, `Layout.ini`, and `Ag*.db` files from the Prefetch directory.
- The collector preserves raw evidence for later parser or external-tool analysis; it does not parse Prefetch internals during collection.
- Files outside the targeted Prefetch patterns are not collected by this contract.

## Validation

- `cargo test --locked prefetch`
- `cargo test --locked`
- Desktop Collection tab packages Prefetch through the same collector path when `Prefetch` is selected.

## Update Checklist

- Update this page if the targeted Prefetch filename filters change.
- Update this page if the manifest schema or centralized archive layout changes.
- Update this page if Prefetch collection expands beyond VSS-backed targeted file copy.