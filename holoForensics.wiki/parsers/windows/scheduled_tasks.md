# windows_scheduled_tasks

## Summary

Artemis-backed Windows parser for scheduled task artifacts discovered inside evidence packages.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_scheduled_tasks_collection`

## Inputs

- Legacy `.job` files under `Windows/Tasks`
- Modern task files under `Windows/System32/Tasks`
- Files copied by `windows_scheduled_tasks_collection`

## Output

- Writes JSONL scheduled task records emitted by the vendored Artemis parser runtime.
- Merges all matched scheduled task sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover both legacy and modern scheduled task inputs.

## Update Checklist

- Update this page if scheduled task discovery or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
