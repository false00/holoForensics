# windows_srum_collection

## Summary

Native Rust live collector for Windows SRUM acquisition. The collector uses a VSS snapshot, copies the SRU folder from the snapshot rather than the live path, and includes `SOFTWARE` and `SYSTEM` as supporting hives for parser enrichment and context.

This contract now feeds the `windows_srum` parser family. The current Artemis-backed adapter anchors on preserved `SRUDB.dat` while the supporting hives remain available in the archive for enrichment or external analysis.

## Source

- `src/collections/windows/srum.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`

## Mode

- `vss`: default and only current acquisition mode. Creates or reuses a native Windows VSS snapshot, copies SRUM files from the point-in-time snapshot, hashes source and destination bytes, and records copy failures honestly.

## CLI

```powershell
holo-forensics collect-srum --volume C: --out-dir C:\temp\srum --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege`.
- Creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when SRUM is collected with Registry, EVTX, `$MFT`, `$LogFile`, INDX, USN, Browser Artifacts, Jump Lists, or LNK Files for the same volume.
- Copies every file directly under `C:\Windows\System32\sru\` when present.
- Copies supporting hives:
  - `C:\Windows\System32\config\SOFTWARE`
  - `C:\Windows\System32\config\SYSTEM`
- Computes SHA-256 for each VSS source and copied destination file.
- Verifies source and destination hashes match.
- Records file metadata, copied files, and failures in the centralized manifest.
- Deletes owned VSS snapshots after collection.

## Output

- `C/Windows/System32/sru/*`
- `C/Windows/System32/config/SOFTWARE`
- `C/Windows/System32/config/SYSTEM`
- `$metadata/collectors/C/windows_srum/manifest.json`
- `$metadata/collectors/C/windows_srum/collection.log`

The manifest uses schema `windows_srum_collection_v1` and records source root, source globs, VSS metadata when used, enabled privileges, copied file metadata, SHA-256 values, failures, and warnings.

## Current Scope

- SRUM acquisition is implemented through VSS file copy.
- The collector copies the whole SRU folder at one level deep and includes `SOFTWARE` and `SYSTEM`.
- Broader registry context remains covered by `windows_registry_collection`.
- No SRUM parsing is performed during collection.

## Validation

- `cargo test srum`
- `cargo test`
- Desktop Collection tab packages SRUM through the same collector path when `SRUM` is selected.

## Update Checklist

- Update this page if SRUM collection adds recursive folder traversal.
- Update this page if additional supporting hives are added directly to this collector.
- Update this page if the manifest schema or archive layout changes.

