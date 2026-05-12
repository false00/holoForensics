# windows_recycle_bin_info2

## Summary

Native Rust parser for Windows XP recycle-bin `INFO2` artifacts.

The live collection contract bound to this parser now preserves both modern `$Recycle.Bin` and legacy `Recycler` roots, but this parser still emits records only from XP or Server 2003 `INFO2` files.

## Source

- `src/parsers/windows/recycle_bin_info2.rs`

## Inputs

- Windows XP `INFO2`
- Preserved live collection archives from `windows_recycle_bin_info2_collection` when `INFO2` exists under `Recycler`

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
