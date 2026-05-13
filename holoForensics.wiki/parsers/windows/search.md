# windows_search

## Summary

Artemis-backed Windows parser for Windows Search databases supplied inside evidence packages. The bound collection contract is parser-only today; Holo Forensics does not yet ship a live Windows Search collector.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_search_collection`

## Inputs

- `Windows.edb`
- `Windows.db`

## Output

- Writes JSONL search records emitted by the vendored Artemis parser runtime.
- Merges all matched Windows Search database sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover Windows Search databases from supported Windows versions.

## Update Checklist

- Update this page if accepted search database filenames or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
