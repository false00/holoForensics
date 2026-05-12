# windows_indx_collection

## Summary

Native Rust live collector for NTFS directory index artifacts. The default mode creates or reuses a VSS snapshot, opens the snapshot device as a raw NTFS volume, walks directory MFT records, and preserves `$INDEX_ROOT:$I30`, `$INDEX_ALLOCATION:$I30`, and `$BITMAP:$I30` values in a collector-owned rawpack.

INDX is not one global NTFS file. It is directory-scoped index metadata, so this collector enumerates directory records rather than looking for a single `$INDX` path.

## Source

- `src/collections/windows/indx.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`

## Modes

- `vss`: default. Creates or reuses a native Windows VSS snapshot, opens the snapshot device without a trailing slash, parses NTFS metadata, and collects directory `$I30` attributes from the point-in-time snapshot.
- `raw`: explicit live raw mode. Opens `\\.\C:` read-only with shared read/write/delete access and records a warning that the volume is a moving target.

Raw mode is not equivalent to VSS or a dead-box image. INDX and directory metadata can change during live acquisition.

## CLI

```powershell
holo-forensics collect-indx --volume C: --out-dir C:\temp\indx --elevate
holo-forensics collect-indx --volume C: --mode raw --out-dir C:\temp\indx --elevate
holo-forensics collect-indx --all-volumes --mode vss --out-dir E:\Evidence --elevate
holo-forensics collect-indx --volume C: --out-dir C:\temp\indx --max-directories 1000 --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeManageVolumePrivilege`, and `SeRestorePrivilege`.
- In VSS mode, creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when INDX is collected with `$MFT`, `$LogFile`, SRUM, Registry, USN, EVTX, Browser Artifacts, Jump Lists, or LNK Files for the same volume.
- Opens the VSS snapshot device or live volume as a raw NTFS device.
- Reads and validates the NTFS boot sector.
- Parses NTFS with the existing `ntfs` crate.
- Sizes the `$MFT` stream and walks MFT records.
- Collects in-use directory records by default. `--include-deleted-dirs` also inspects deleted directory records that can still be parsed.
- For each directory record, preserves `$INDEX_ROOT:$I30`, `$INDEX_ALLOCATION:$I30`, and `$BITMAP:$I30` attribute values when present.
- Writes raw attribute bytes into `C/INDX.rawpack`, preserving the attribute bytes as read rather than parsing and rewriting entries.
- Hashes every rawpack entry and the final rawpack with SHA-256.
- Records directory record number, sequence, path/name hint, attribute type, resident status, rawpack offset, length, data runs, and INDX signature counts.
- Writes centralized manifest and collection log.
- Deletes owned VSS snapshots after collection.

## Output

- `C/INDX.rawpack`
- `C/INDX.rawpack.sha256`
- `$metadata/collectors/C/windows_indx/manifest.json`
- `$metadata/collectors/C/windows_indx/collection.log`

The manifest uses schema `windows_indx_collection_v1` and records source device, acquisition mode, VSS metadata when used, NTFS geometry, MFT record count, rawpack hash, per-entry hashes, directory record metadata, data run metadata when available, enabled privileges, warnings, and validation counts.

## Current Scope

- Full-volume directory record walking is implemented.
- VSS is the default live collection mode.
- Raw live mode is available only when explicitly selected.
- Default collection includes in-use directory records. Deleted directory record inspection is opt-in.
- The collector preserves raw `$I30` attribute values and records path/name hints, but it does not yet emit parsed active or slack index entries as CSV/JSON.
- The standard size policy is `real_size`. Allocated-size slack beyond the attribute real size is not collected yet.

## Validation

- `cargo test indx`
- `cargo test`
- Desktop Collection tab packages INDX through the same collector path when `INDX Records` is selected.

## Update Checklist

- Update this page if allocated-size slack collection is added.
- Update this page if parsed active or slack INDX entry export is added.
- Update this page if targeted path or MFT-record selection is added.
- Update this page if the manifest schema or archive layout changes.

