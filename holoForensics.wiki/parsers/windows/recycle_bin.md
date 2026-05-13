# windows_recycle_bin

## Summary

Artemis-backed Windows parser for modern Recycle Bin metadata discovered inside evidence packages.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_recycle_bin_info2_collection`

## Inputs

- Modern Recycle Bin `$I*` metadata files copied by `windows_recycle_bin_info2_collection`
- Preserved files under modern `$Recycle.Bin` roots

## Output

- Writes JSONL modern Recycle Bin metadata records emitted by the vendored Artemis parser runtime.
- Merges all matched `$I*` sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover modern `$I*` metadata from supported Windows versions.

## Update Checklist

- Update this page if Recycle Bin discovery or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
