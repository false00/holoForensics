# windows_wmi_persistence

## Summary

Artemis-backed Windows parser for WMI persistence data discovered in preserved repository content.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_wmi_repository_collection`

## Inputs

- WMI repository `OBJECTS.DATA` files copied by `windows_wmi_repository_collection`
- Preserved repository roots such as `Repository` and `Repository.*`

## Output

- Writes JSONL WMI persistence records emitted by the vendored Artemis parser runtime.
- Merges all matched repository sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover repository inputs from supported Windows versions.

## Update Checklist

- Update this page if repository discovery or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
