# linux_shell_history

## Summary

Native Rust parser for Linux shell history files.

## Source

- `src/parsers/linux_shell_history.rs`

## Inputs

- `.bash_history`
- `.zsh_history`

## Output

- Writes JSONL records for parsed shell history entries under the family output directory.
- Writes a family log with per-file skip or record counts.

## Validation

- `cargo test`
- Update validation notes when shell-history parsing rules change.

## Update Checklist

- Update this page if supported shell history formats change.
- Update this page if timestamp handling or emitted fields change.
- Update this page if detection paths or output semantics change.