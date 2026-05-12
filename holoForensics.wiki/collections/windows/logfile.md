# windows_logfile_collection

## Summary

Native Rust live collector for the NTFS `$LogFile` transaction log. The default mode creates or reuses a VSS snapshot, opens the snapshot device as a raw NTFS volume, reads MFT record 2, verifies it resolves to `$LogFile`, streams the unnamed `$DATA` attribute to evidence output, hashes it, and records collection metadata.

## Source

- `src/collections/windows/logfile.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`

## Modes

- `vss`: default. Creates or reuses a native Windows VSS snapshot, opens the snapshot device without a trailing slash, parses NTFS metadata, and extracts `$LogFile` from the point-in-time snapshot.
- `raw`: explicit live raw mode. Opens `\\.\C:` read-only with shared read/write/delete access and records a warning that `$LogFile` may change during acquisition.

VSS is preferred because `$LogFile` is actively updated on live systems and is more useful when collected from the same point-in-time snapshot as `$MFT`.

## CLI

```powershell
holo-forensics collect-logfile --volume C: --out-dir C:\temp\logfile --elevate
holo-forensics collect-logfile --volume C: --mode raw --out-dir C:\temp\logfile --elevate
holo-forensics collect-logfile --all-volumes --mode vss --out-dir E:\Evidence --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeManageVolumePrivilege`, and `SeRestorePrivilege`.
- In VSS mode, creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when `$LogFile` is collected with `$MFT`, INDX, SRUM, Registry, USN, EVTX, and/or Browser Artifacts for the same volume.
- Opens the VSS snapshot device or live volume as a raw NTFS device.
- Reads and validates the NTFS boot sector.
- Parses NTFS with the existing `ntfs` crate.
- Opens MFT record 2 (`$LogFile`) and verifies the `$FILE_NAME` attribute.
- Resolves the unnamed `$DATA` stream.
- Streams the `$DATA` value to `C/$LogFile.bin` without parsing or rewriting records.
- Computes SHA-256 while writing and emits `C/$LogFile.bin.sha256`.
- Validates output size against the `$LogFile` data size and checks output pages for `RSTR` or `RCRD` signatures.
- Writes centralized manifest and collection log.
- Deletes owned VSS snapshots after collection.

## Output

- `C/$LogFile.bin`
- `C/$LogFile.bin.sha256`
- `$metadata/collectors/C/windows_logfile/manifest.json`
- `$metadata/collectors/C/windows_logfile/collection.log`

The manifest uses schema `windows_logfile_collection_v1` and records source device, acquisition mode, VSS metadata when used, NTFS geometry, MFT LCN, MFT mirror LCN, record size, `$LogFile` real size, data run metadata when available, output hash, enabled privileges, warnings, and validation counts.

## Current Scope

- `$LogFile` acquisition is implemented.
- VSS is the default live collection mode.
- Raw live mode is available only when explicitly selected.
- `$MFT` remains covered by `windows_mft_collection`.
- INDX directory index attributes are collected by `windows_indx_collection`.
- `$UsnJrnl:$J` remains covered by `windows_usn_journal_collection`.
- `$Bitmap` is not collected yet.

## Validation

- `cargo test logfile`
- `cargo test`
- Desktop Collection tab packages `$LogFile` through the same collector path when `$LogFile` is selected.

## Update Checklist

- Update this page if `$Bitmap` acquisition or an `ntfs-core` bundle mode is added.
- Update this page if the manifest schema or archive layout changes.
- Update this page if the collector begins parsing `$LogFile` records rather than only acquiring raw bytes.

