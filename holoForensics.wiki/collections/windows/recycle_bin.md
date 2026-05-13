# windows_recycle_bin_info2_collection

## Summary

Native Rust live collector for Windows Recycle Bin acquisition under the existing `windows_recycle_bin_info2_collection` contract. The collector uses a VSS snapshot, copies both modern `$Recycle.Bin` and legacy `Recycler` roots exactly as they exist on disk, preserves root-level files and nested recycled-directory content, hashes each copied file, and writes a JSONL artifact inventory for downstream review.

This contract now feeds `windows_recycle_bin` for modern `$I*` metadata and `windows_recycle_bin_info2` for XP or Server 2003 `INFO2`. Modern `$R` payload files remain preserved raw for later parsing or external-tool analysis.

## Source

- `src/collections/windows/recycle_bin.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`
- Bound parser pages: `holoForensics.wiki/parsers/windows/recycle_bin.md` and `holoForensics.wiki/parsers/windows/recycle_bin_info2.md`

## Mode

- `vss`: default and only current acquisition mode. Creates or reuses a native Windows VSS snapshot, copies raw Recycle Bin files from the point-in-time snapshot, hashes source and destination bytes, and records copy failures honestly.

## CLI

```powershell
holo-forensics collect-recycle-bin --volume C: --out-dir C:\temp\recycle-bin --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege`.
- Creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when Recycle Bin is collected with Registry, EVTX, SRUM, Prefetch, Browser Artifacts, Jump Lists, LNK Files, `$MFT`, `$LogFile`, INDX, or USN for the same volume.
- Enumerates both Recycle Bin roots from the snapshot when present:
  - `C:\$Recycle.Bin`
  - `C:\Recycler`
- Preserves exact on-disk names and layout instead of restoring original names or flattening by source path.
- Recursively copies nested `$R...` directories and their contents when recycled folders exist.
- Copies root-level files such as `desktop.ini` and any unexpected files placed directly under the Recycle Bin root.
- Computes SHA-256 for each VSS source file and copied destination file.
- Verifies source and destination hashes match.
- Writes `C/recycle_bin_manifest.jsonl` with one JSON object per copied file, including source path, VSS path, root kind, SID when derivable, artifact kind, pair identifier when derivable, timestamps, attributes, and SHA-256.
- Records file metadata, copied files, warnings, and failures in the centralized manifest.
- Deletes owned VSS snapshots after collection.

## Output

- `C/$Recycle.Bin/**/*`
- `C/Recycler/**/*`
- `C/recycle_bin_manifest.jsonl`
- `$metadata/collectors/C/windows_recycle_bin/manifest.json`
- `$metadata/collectors/C/windows_recycle_bin/collection.log`

The manifest uses schema `windows_recycle_bin_info2_collection_v1` and records source roots, VSS metadata when used, enabled privileges, copied file metadata, SHA-256 values, failures, and warnings.

## Current Scope

- Recycle Bin acquisition is implemented through VSS targeted file copy.
- The collector preserves raw Recycle Bin evidence for later analysis; it does not restore original names during collection.
- The JSONL artifact inventory is intended to make preserved Recycle Bin content easier to review and correlate before broader parser support lands.
- Modern `$I` and `$R` pairing is identified heuristically in the artifact inventory, but the collector does not assume every pair is complete.
- Alternate data streams are not emitted as separate archive entries yet.

## Validation

- `cargo test recycle_bin`
- `cargo test --locked`
- Desktop Collection tab packages Recycle Bin through the same collector path when `Recycle Bin` is selected.

## Update Checklist

- Update this page if supported Recycle Bin roots, raw-copy behavior, or pairing heuristics change.
- Update this page if ADS handling, stream preservation, or privilege requirements change.
- Update this page if the JSONL artifact manifest schema or centralized manifest schema changes.