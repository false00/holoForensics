# windows_browser_history

## Summary

Native Rust parser for Windows browser history databases.

## Source

- `src/parsers/windows/browser_history.rs`
- Collection binding: `windows_browser_artifacts_collection`

## Inputs

- Chrome `History`
- Edge `History`
- Firefox history databases

## Output

- Writes one JSONL record per parsed browser history row.
- The family covers Chrome, Edge, and Firefox through platform-specific collectors.
- Writes a family log with file-level skip and record-count information.

## Validation

- `cargo test`
- Browser coverage should be verified with representative Chrome, Edge, and Firefox history databases.

## Update Checklist

- Update this page if supported browsers or profile discovery rules change.
- Update this page if the browser parser is rebound to a different collection contract.
- Update this page if SQL queries, emitted fields, or timestamp normalization change.
- Update this page if validation coverage changes for Chrome, Edge, or Firefox.
