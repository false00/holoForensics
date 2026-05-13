# windows_srum

## Summary

Artemis-backed Windows parser for SRUM data discovered inside evidence packages.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_srum_collection`

## Inputs

- `SRUDB.dat` copied by `windows_srum_collection`

## Output

- Writes JSONL SRUM records emitted by the vendored Artemis parser runtime.
- Merges all matched `SRUDB.dat` sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover SRUM databases from supported Windows versions.

## Update Checklist

- Update this page if SRUM discovery or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
