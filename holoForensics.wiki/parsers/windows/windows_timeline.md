# windows_timeline

## Summary

Native Rust parser for Windows Timeline activity databases.

## Source

- `src/parsers/windows/windows_timeline.rs`

## Inputs

- `ActivitiesCache.db`

## Output

- Writes JSONL records for parsed timeline activity rows under the family output directory.
- Writes a family log with file-level skip and record-count information.

## Validation

- `cargo test`
- Timeline coverage should be verified with representative `ActivitiesCache.db` artifacts.

## Update Checklist

- Update this page if the SQL queries or emitted activity fields change.
- Update this page if artifact discovery rules change.
- Update this page if validation coverage changes.
