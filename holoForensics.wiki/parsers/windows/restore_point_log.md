# windows_restore_point_log

## Summary

Native Rust parser for Windows restore-point `rp.log` artifacts.

## Source

- `src/parsers/windows/restore_point_log.rs`

## Inputs

- Restore-point `rp.log`

## Output

- Writes JSONL records for parsed restore-point log entries under the family output directory.
- Writes a family log with file-level skip and record-count information.

## Validation

- `cargo test`
- Revalidate with a representative restore-point artifact whenever parsing logic or field mapping changes.

## Update Checklist

- Update this page if input detection changes.
- Update this page if emitted fields or record granularity change.
- Update this page if validation status changes.

