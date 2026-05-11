# macos_quarantine_events

## Summary

Native Rust parser for macOS quarantine event databases.

## Source

- `src/parsers/macos_artifacts.rs`

## Inputs

- `com.apple.LaunchServices.QuarantineEventsV2`

## Output

- Writes one JSONL record per quarantine event.
- Includes user context, download and origin URLs, agent metadata, event UUID, and source path.
- Writes a family log with file and record counts.

## Validation

- `cargo test`
- Revalidate with a macOS quarantine database when SQL shape or field mapping changes.

## Update Checklist

- Update this page if the input database name or location rules change.
- Update this page if emitted fields or time conversion rules change.
- Update this page if quarantine-specific parsing limitations change.