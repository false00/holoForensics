# windows_usn_journal_collection

## Purpose

This collection acquires the raw `$Extend\$UsnJrnl:$J` stream from a live Windows NTFS volume without parsing individual USN records during collection.

## Source

- `src/collections/windows/usn_journal.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`

## Current Status

- Implemented in the existing `holo-forensics` binary
- Current collection modes are `direct-stream`, `vss-snapshot`, and `vss-raw-ntfs`
- Default collection mode is `vss-raw-ntfs`
- Default output is compact active-window capture rather than the full logical sparse stream
- Parser family `windows_usn_journal` is now bound to this collection
- The desktop Collection section wraps the raw output and collector manifest into a collection zip for immediate Parse Mode inspection

## CLI

```powershell
holo-forensics collect-usn-journal --volume C: --out C:\temp\C_usn_journal_J.bin
```

Optional metadata override:

```powershell
holo-forensics collect-usn-journal --volume C: --out C:\temp\C_usn_journal_J.bin --metadata C:\temp\C_usn_journal_J.metadata.json
```

Optional diagnostic log override:

```powershell
holo-forensics collect-usn-journal --volume C: --out C:\temp\C_usn_journal_J.bin --diagnostic-log C:\temp\C_usn_journal_J.bin.diagnostic.log
```

Optional UAC self-elevation:

```powershell
holo-forensics collect-usn-journal --volume C: --out C:\temp\C_usn_journal_J.bin --elevate
```

VSS-backed snapshot mode:

```powershell
holo-forensics collect-usn-journal --volume C: --out C:\temp\C_usn_journal_J.bin --mode vss-snapshot --elevate
```

VSS-backed raw NTFS mode:

```powershell
holo-forensics collect-usn-journal --volume C: --out C:\temp\C_usn_journal_J.bin --mode vss-raw-ntfs --elevate
```

VSS-backed raw NTFS sparse logical mode:

```powershell
holo-forensics collect-usn-journal --volume C: --out C:\temp\C_usn_journal_J.bin --mode vss-raw-ntfs --sparse --elevate
```

## Current Behavior

- Can trigger a UAC prompt and relaunch itself when `--elevate` is supplied
- Attempts to enable `SeBackupPrivilege`, `SeManageVolumePrivilege`, and `SeRestorePrivilege`
- `direct-stream` tries both `\\?\C:\$Extend\$UsnJrnl:$J` and `\\.\C:\$Extend\$UsnJrnl:$J` with shared read/write/delete access
- VSS-backed modes create and delete temporary `Win32_ShadowCopy` snapshots through native Windows COM/WMI APIs from Rust; the collector does not shell out to PowerShell for snapshot lifecycle management
- When the desktop/archive workflow collects USN with Registry, EVTX, MFT, `$LogFile`, INDX, SRUM, and/or Browser Artifacts for the same volume, the workflow creates one shared `Win32_ShadowCopy` and passes it into the VSS-backed collectors; standalone USN CLI collection still owns its own snapshot lifecycle
- `vss-snapshot` reads `$Extend\$UsnJrnl:$J` from the snapshot device path
- `vss-raw-ntfs` opens the snapshot device itself, parses NTFS, locates `$Extend\$UsnJrnl:$J`, and reads the logical bytes of the named `$DATA` stream through NTFS structures instead of a protected file path
- By default writes only the active USN window `[FirstUsn, NextUsn)` into the requested output file as a compact dense capture
- `--sparse` preserves the full logical stream layout, marks the output file sparse, seeks over hole runs, records run extents plus allocated bytes written in the sidecar, and hashes allocated ranges instead of synthetic hole bytes when used with `vss-raw-ntfs`
- Computes SHA-256 while writing
- Queries live journal metadata with `FSCTL_QUERY_USN_JOURNAL`
- Writes a JSON sidecar with collection time, collector metadata, journal metadata, warnings, and shadow-copy metadata when a VSS-backed mode is used
- The paired parser uses the standalone sidecar or centralized zip manifest `FirstUsn`, `NextUsn`, `output_logical_base`, and sparse `data_runs` metadata to preserve original stream offsets while avoiding hole-region scans when sparse logical output is used
- Writes a failure sidecar when collection fails after startup, including blocked UAC relaunches, the failure stage, error details, enabled privileges, VSS lifecycle, and whether partial raw output was produced
- Stamps each sidecar with metadata schema `usn_raw_collection_v1`
- Writes a persistent diagnostic log so elevated relaunch failures can be inspected after the child exits

## Output

- Raw stream output: `C_usn_journal_J.bin`
- Metadata sidecar: `C_usn_journal_J.bin.metadata.json` by default
- Diagnostic log: `C_usn_journal_J.bin.diagnostic.log` by default

When the desktop Collection section is used, the generated collection zip currently contains:

- `C/$Extend/$UsnJrnl/$J.bin`
- `$metadata/collectors/C/windows_usn_journal/manifest.json`

The diagnostic log stays in the staging directory next to the collected files and is not added to the zip.

The standalone metadata sidecar and centralized zip manifest record:

- Artifact name and source path
- Metadata schema version
- Source access method such as `direct_stream`, `vss_direct_stream`, or `vss_raw_ntfs`
- Collection status such as `succeeded` or `failed`
- Failure stage and error details when collection fails
- Elevation state and enabled privileges
- Whether partial raw output was produced
- Output mode such as `dense_logical` or `sparse_logical`
- Source logical size and output logical base when compact active-window output is used
- Collection time in UTC
- Output SHA-256 plus the recorded hash scope such as `logical_stream` or `allocated_ranges`
- Logical size, bytes written, allocated bytes written, and whether sparse holes were preserved
- Data runs with logical offset, optional volume offset, length, and sparse/non-sparse state when sparse logical output is used
- Live journal metadata such as `UsnJournalID`, `FirstUsn`, and `NextUsn`
- Volume serial number and file system type when available
- Shadow-copy lifecycle including id, device path, context, create/delete state, and whether the snapshot was shared by the archive workflow when a VSS-backed mode is used
- Collection warnings such as privilege or metadata-query failures

## Current Limitations

- No allocated-range compact mode yet
- No raw-volume NTFS fallback yet
- `vss-snapshot` can create a temporary shadow copy, but Windows may still deny access to `$Extend\$UsnJrnl:$J` through the snapshot device path
- `vss-raw-ntfs` uses raw device open, NTFS parse, `$Extend\$UsnJrnl:$J` resolution, and active logical-byte streaming
- Default active-window output preserves the original logical base in metadata while avoiding unnecessary sparse-hole output
- Sparse logical output currently uses exact NTFS data runs for normal non-resident streams and a clustered sparse fallback for other NTFS attribute-value layouts
- The parser currently supports USN record versions 2 and 3; unsupported major versions are skipped with a log entry

## Follow-up Expectations

- Add allocated-range output mode when direct-stream or snapshot collection is not sufficient
- Add live raw-volume NTFS fallback after the VSS raw-NTFS path
- Expand parser coverage if future collections encounter USN record version 4 or additional sidecar schemas

