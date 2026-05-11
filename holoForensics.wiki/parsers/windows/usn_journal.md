# windows_usn_journal

## Summary

Native Rust parser for raw NTFS `$Extend\$UsnJrnl:$J` streams collected by `windows_usn_journal_collection`.

## Source

- `src/parsers/windows/usn_journal.rs`

## Inputs

- Raw USN stream files named like legacy `C_usn_journal_J.bin` or path-preserving archive entries like `C/$Extend/$UsnJrnl/$J.bin`
- Optional standalone sidecar `C_usn_journal_J.bin.metadata.json`
- Optional centralized collection zip manifest `$metadata/collectors/C/windows_usn_journal/manifest.json`

## Output

- Writes one JSONL record per parsed USN record.
- Supports USN record versions 2 and 3.
- Uses manifest or sidecar `FirstUsn` and `NextUsn` values when present to bound parsing to the active journal window.
- Uses manifest or sidecar `output_logical_base` when present so emitted `record_offset` values still refer to the original logical USN stream offsets for compact active-window captures.
- Uses manifest or sidecar sparse `data_runs` metadata when present to skip sparse hole regions instead of scanning the full logical stream.
- Emits a family log with file-level skips, unsupported-version notices, and malformed-record notices.

## Validation

- `cargo test usn_journal`
- Synthetic unit coverage for sidecar range handling plus USN record versions 2 and 3
- Coverage should include dense active-window and sparse logical VSS raw-NTFS artifacts.

## Update Checklist

- Update this page if supported USN record versions change.
- Update this page if metadata manifest requirements, sparse-range handling, or emitted fields change.
- Update this page if validation coverage changes.
