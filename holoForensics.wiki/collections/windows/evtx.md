# windows_evtx_collection

## Summary

Native Rust live collector for Windows Event Log files. The first implementation performs a physical `.evtx` acquisition from a VSS snapshot so the copied logs represent a stable point-in-time view instead of the live, locked log files.

## Source

- `src/collections/windows/evtx.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`

## Workflow

- Normalizes the selected NTFS source volume.
- Uses a native Windows VSS snapshot as the source.
- Reuses the archive workflow's shared VSS snapshot when EVTX is collected with Registry, USN, MFT, `$LogFile`, INDX, SRUM, Browser Artifacts, Jump Lists, or LNK Files for the same volume.
- Enumerates `*.evtx` under `Windows\System32\winevt\Logs` in the snapshot, including `Archive-*.evtx`.
- Copies the physical `.evtx` files without parsing or rewriting them.
- Preserves original Windows archive paths under `C/Windows/System32/winevt/Logs/`.
- SHA-256 hashes the VSS source and copied destination, then records a failure if they differ.
- Records file size, timestamps when available, live path, VSS path, archive path, hash, and failures in the collector manifest.
- Writes an operator-facing collection log beside the manifest.

## CLI

```powershell
holo-forensics collect-evtx --volume C: --out-dir C:\temp\evtx --elevate
```

## Output

- Event logs such as `C/Windows/System32/winevt/Logs/Security.evtx`
- Event logs such as `C/Windows/System32/winevt/Logs/System.evtx`
- Event logs such as `C/Windows/System32/winevt/Logs/Application.evtx`
- Operational logs such as `C/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx`
- Archived logs such as `C/Windows/System32/winevt/Logs/Archive-*.evtx`
- `$metadata/collectors/C/windows_evtx/manifest.json`
- `$metadata/collectors/C/windows_evtx/collection.log`

The manifest uses schema `windows_evtx_collection_v1` and records VSS metadata, source globs, discovered/copied/failed counts, copied file records, and per-file failure records.

## Current Scope

- VSS physical copy is implemented.
- Raw disk mode is intentionally not used for EVTX because VSS is enough for stable point-in-time file copy.
- Logical Event Log API export with `EvtExportLog` is not implemented yet.
- Channel API enumeration with `EvtOpenChannelEnum` / `EvtGetChannelConfigProperty` is not implemented yet, so this first version targets the standard event log directory on the selected volume.

## Validation

- `cargo test evtx`
- `cargo test`
- Desktop Collection tab packages EVTX files through the same collector path when `Windows Event Logs` is selected.

## Update Checklist

- Update this page if channel configuration enumeration is added.
- Update this page if logical `EvtExportLog` exports are added.
- Update this page if the manifest schema or archive layout changes.

