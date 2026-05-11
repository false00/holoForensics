# windows_recycle_bin_info2

## Summary

Native Rust parser for Windows XP recycle-bin `INFO2` artifacts.

## Source

- `src/parsers/windows/recycle_bin_info2.rs`

## Inputs

- Windows XP `INFO2`

## Output

- Writes JSONL records for parsed recycle-bin entries under the family output directory.
- Writes a family log with file-level skip and record-count information.

## Validation

- `cargo test`
- Revalidate with a representative `INFO2` artifact whenever parser logic or emitted fields change.

## Update Checklist

- Update this page if the input artifact scope changes.
- Update this page if emitted fields, path handling, or timestamp handling change.
- Update this page if validation status changes.
