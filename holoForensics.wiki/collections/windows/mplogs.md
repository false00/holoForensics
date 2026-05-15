# windows_mplogs_collection

## Summary

Native Rust live collector for Microsoft Protection Logs acquisition. The collector uses a VSS snapshot, copies Microsoft Defender Support `MPLog*.log` files from the snapshot rather than the live path, hashes both source and destination bytes, and writes centralized collector metadata.

This contract preserves raw MPLog evidence for review and handoff and now feeds the native `windows_mplogs` parser family.

## Source

- `src/collections/windows/mplogs.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`
- Parser binding: `src/parsers/windows/mplogs.rs` -> `windows_mplogs`

## Mode

- `vss`: default and only current acquisition mode. Creates or reuses a native Windows VSS snapshot, copies raw Defender Support MPLog files from the point-in-time snapshot, hashes source and destination bytes, and records copy failures honestly.

## CLI

```powershell
holo-forensics collect-mplogs --volume C: --out-dir C:\temp\mplogs --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege`.
- Creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when Microsoft Protection Logs is collected with Registry, EVTX, SRUM, Prefetch, Scheduled Tasks, WMI Repository, PowerShell Activity, Browser Artifacts, Jump Lists, LNK Files, Recycle Bin, `$MFT`, `$LogFile`, INDX, or USN for the same volume.
- Enumerates `C:\ProgramData\Microsoft\Windows Defender\Support` non-recursively.
- Selects files whose names start with `MPLog` and end with `.log`, case-insensitively.
- Preserves raw file bytes by streaming from the VSS source path to the package output.
- Computes SHA-256 for each VSS source stream and copied destination file.
- Verifies source and destination hashes match.
- Records file metadata, enabled privileges, source directory details, warnings, and failures in the centralized manifest.
- Skips registry and EVTX duplication already covered by other collectors.
- Deletes owned VSS snapshots after collection.

## Output

- `C/ProgramData/Microsoft/Windows Defender/Support/MPLog*.log`
- `$metadata/collectors/C/windows_mplogs/manifest.json`
- `$metadata/collectors/C/windows_mplogs/collection.log`

The manifest uses schema `windows_mplogs_collection_v1` and records source directory metadata, VSS metadata when used, enabled privileges, copied file metadata, SHA-256 values, failures, and warnings.

## Current Scope

- Microsoft Protection Logs acquisition is implemented through VSS-targeted file copy.
- The collector preserves raw Defender Support MPLog files for later parser or external-tool analysis.
- The collector does not parse Defender logs during collection.
- The collector intentionally does not duplicate registry or EVTX acquisition already covered by other collectors.

## Validation

- `cargo test --locked mplogs`
- Desktop Collection tab packages Microsoft Protection Logs through the same collector path when `Microsoft Protection Logs` is selected.
- Parse Mode detects collected `MPLog*.log` files through `windows_mplogs` and emits JSONL records with raw-line preservation.

## Parser Binding

- `windows_mplogs`
- Expected input path pattern inside a collected package: `C/ProgramData/Microsoft/Windows Defender/Support/MPLog*.log`
- Parser output contract: one JSONL record per parsed log line with preserved raw text, normalized key-value fields, event classification, and timestamp assumptions when the log does not carry an explicit timezone.

## Update Checklist

- Update this page if the targeted Defender Support file patterns change.
- Update this page if the manifest schema or centralized archive layout changes.
- Update this page if Microsoft Protection Logs collection expands beyond VSS-backed raw file copy.