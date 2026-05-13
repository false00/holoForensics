# windows_shimdb

## Summary

Artemis-backed Windows parser for application compatibility Shim Database files supplied inside evidence packages. The bound collection contract is parser-only today; Holo Forensics does not yet ship a live Shim DB collector.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_shimdb_collection`

## Inputs

- `.sdb` application compatibility database files

## Output

- Writes JSONL Shim Database records emitted by the vendored Artemis parser runtime.
- Merges all matched Shim DB sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover common Windows application compatibility database inputs.

## Update Checklist

- Update this page if accepted Shim DB filenames or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
