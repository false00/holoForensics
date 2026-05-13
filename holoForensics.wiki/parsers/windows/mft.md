# windows_mft

## Summary

Artemis-backed Windows parser for raw NTFS `$MFT` evidence discovered inside evidence packages.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_mft_collection`

## Inputs

- Raw `$MFT` evidence copied by `windows_mft_collection`
- Typical archive payloads such as `C/$MFT` or raw extractor outputs preserved in the package

## Output

- Writes JSONL MFT records emitted by the vendored Artemis parser runtime.
- Merges all matched `$MFT` sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover raw `$MFT` inputs from supported NTFS volumes.

## Update Checklist

- Update this page if `$MFT` discovery or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
