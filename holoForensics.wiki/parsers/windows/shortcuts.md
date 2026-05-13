# windows_shortcuts

## Summary

Artemis-backed Windows parser for raw shortcut `.lnk` files discovered inside evidence packages.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_lnk_collection`

## Inputs

- Raw `.lnk` files copied by `windows_lnk_collection`
- Typical sources include Recent, Office Recent, Desktop, and Start Menu paths

## Output

- Writes JSONL shortcut records emitted by the vendored Artemis parser runtime.
- Merges all matched shortcut sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover `.lnk` files from multiple user locations.

## Update Checklist

- Update this page if shortcut discovery or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
