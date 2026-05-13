# windows_users

## Summary

Artemis-backed Windows parser for local user and RID data discovered in offline `SAM` hives.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_registry_collection`

## Inputs

- `SAM` registry hives copied by `windows_registry_collection`

## Output

- Writes JSONL local user records emitted by the vendored Artemis parser runtime.
- Merges all matched `SAM` hive sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover `SAM` inputs from supported Windows versions.

## Update Checklist

- Update this page if hive discovery or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
