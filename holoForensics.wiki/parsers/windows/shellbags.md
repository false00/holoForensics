# windows_shellbags

## Summary

Artemis-backed Windows parser for Shellbags data discovered in offline user hives.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_registry_collection`

## Inputs

- `NTUSER.DAT` user registry hives
- `USRCLASS.DAT` user class hives

## Output

- Writes JSONL Shellbags records emitted by the vendored Artemis parser runtime.
- Merges all matched Shellbags hive sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover both `NTUSER.DAT` and `USRCLASS.DAT` inputs.

## Update Checklist

- Update this page if hive discovery or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
