# windows_amcache

## Summary

Artemis-backed Windows parser for `Amcache.hve` execution and install inventory data.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_registry_collection`

## Inputs

- `Amcache.hve` copied by `windows_registry_collection`

## Output

- Writes JSONL Amcache records emitted by the vendored Artemis parser runtime.
- Merges all matched Amcache hive sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover Amcache inputs from supported Windows versions.

## Update Checklist

- Update this page if Amcache discovery or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
