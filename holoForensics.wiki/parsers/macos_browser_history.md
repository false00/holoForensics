# macos_browser_history

## Summary

Native Rust parser for macOS Chrome history.

## Source

- `src/parsers/macos_artifacts.rs`

## Inputs

- Chrome `History` SQLite databases on macOS collections.

## Output

- Writes one JSONL record per parsed browser history row.
- Includes browser identity, user context, URL/title fields, visit counts, and source path.
- Writes a family log with file and record counts.

## Validation

- `cargo test`
- Revalidate with a representative macOS Chrome history database when SQL shape or timestamp conversion changes.

## Update Checklist

- Update this page if supported macOS browsers expand beyond Chrome.
- Update this page if SQL queries, emitted fields, or time conversion rules change.
- Update this page if artifact detection paths change.
