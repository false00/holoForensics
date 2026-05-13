# windows_jump_lists

## Summary

Artemis-backed Windows parser for Jump List files discovered inside evidence packages.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_jump_lists_collection`

## Inputs

- `*.automaticDestinations-ms`
- `*.customDestinations-ms`
- Files copied by `windows_jump_lists_collection`

## Output

- Writes JSONL Jump List records emitted by the vendored Artemis parser runtime.
- Merges all matched Jump List sources into one family output and one family log.
- Passes the exact collected Jump List file path into Artemis parse mode so emitted evidence paths stay rooted in the extracted collection instead of the live host profile.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- `cargo test jumplists_configuration_preserves_alt_dir --package holo-forensics`
- Focused parse-mode validation against a real extracted `.automaticDestinations-ms` file should confirm the emitted `evidence` field remains under the extracted output tree.
- Representative validation should cover both Automatic and Custom Jump Lists.

## Update Checklist

- Update this page if Jump List discovery or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
