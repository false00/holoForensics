# windows_prefetch

## Summary

Artemis-backed Windows parser for Prefetch `.pf` files discovered inside evidence packages.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_prefetch_collection`

## Inputs

- Windows Prefetch `.pf` files such as `C/Windows/Prefetch/APP.EXE-XXXXXXXX.pf`
- Files copied by `windows_prefetch_collection`

## Output

- Writes JSONL Prefetch records emitted by the vendored Artemis parser runtime.
- Merges all matched Prefetch sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parsers::windows::artemis::tests::build_prefetch_creates_one_plan_per_prefetch_directory -- --exact`
- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover multiple Prefetch files from the same archive.

## Update Checklist

- Update this page if Prefetch discovery rules or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
