# windows_mft_collection

## Summary

Native Rust live collector for the NTFS Master File Table. The default mode creates a VSS snapshot, opens the snapshot device as a raw NTFS volume, locates `$MFT` record 0, streams the unnamed `$DATA` attribute to evidence output, hashes it, and records collection metadata.

## Source

- `src/collections/windows/mft.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`

## Modes

- `vss`: default. Creates or reuses a native Windows VSS snapshot, opens the snapshot device without a trailing slash, parses NTFS metadata, and extracts `$MFT` from the point-in-time snapshot.
- `raw`: explicit live raw mode. Opens `\\.\C:` read-only with shared read/write/delete access and records a warning that the volume is a moving target.

Raw mode is not equivalent to a dead-box image. It exists for cases where VSS is unavailable, blocked, or too slow.

## CLI

```powershell
holo-forensics collect-mft --volume C: --out-dir C:\temp\mft --elevate
holo-forensics collect-mft --volume C: --mode raw --out-dir C:\temp\mft --elevate
holo-forensics collect-mft --all-volumes --mode vss --out-dir E:\Evidence --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeManageVolumePrivilege`, and `SeRestorePrivilege`.
- In VSS mode, creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when MFT is collected with Registry, USN, EVTX, `$LogFile`, INDX, SRUM, Browser Artifacts, Jump Lists, or LNK Files for the same volume.
- Opens the VSS snapshot device or live volume as a raw NTFS device.
- Reads and validates the NTFS boot sector.
- Parses NTFS with the existing `ntfs` crate.
- Opens record 0 (`$MFT`) and resolves the unnamed `$DATA` stream.
- Streams the `$DATA` value to `C/$MFT.bin` without parsing or rewriting records.
- Computes SHA-256 while writing and emits `C/$MFT.bin.sha256`.
- Validates output size against the `$MFT` data size and checks record 0 has a `FILE` signature.
- Writes centralized manifest and collection log.
- Deletes owned VSS snapshots after collection.

## Output

- `C/$MFT.bin`
- `C/$MFT.bin.sha256`
- `$metadata/collectors/C/windows_mft/manifest.json`
- `$metadata/collectors/C/windows_mft/collection.log`

The manifest uses schema `windows_mft_collection_v1` and records source device, acquisition mode, VSS metadata when used, NTFS geometry, MFT LCN, MFT mirror LCN, record size, `$MFT` real size, data run metadata when available, output hash, enabled privileges, warnings, and validation counts.

## Current Scope

- `$MFT` acquisition is implemented.
- VSS is the default live collection mode.
- Raw live mode is available only when explicitly selected.
- `$LogFile` is collected by `windows_logfile_collection`.
- INDX directory index attributes are collected by `windows_indx_collection`.
- `$Bitmap` is not collected by this collector yet.
- `$UsnJrnl:$J` remains covered by `windows_usn_journal_collection`.

## Validation

- `cargo test mft`
- `cargo test`
- Desktop Collection tab packages `$MFT` through the same collector path when `$MFT` is selected.

## Update Checklist

- Update this page if `$Bitmap` acquisition is added.
- Update this page if the manifest schema or archive layout changes.
- Update this page if the extractor changes from logical `$DATA` streaming to explicit manual run-copy behavior.

