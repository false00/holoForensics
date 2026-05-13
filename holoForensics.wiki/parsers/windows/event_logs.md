# windows_event_logs

## Summary

Artemis-backed Windows parser for EVTX event logs discovered inside evidence packages.

## Source

- `src/parsers/windows/artemis.rs`
- Vendored Artemis workspace: `third_party/artemis` via the local `artemis_forensics` path dependency in `Cargo.toml`
- Collection binding: `windows_evtx_collection`

## Inputs

- `.evtx` files under preserved Windows log roots such as `C/Windows/System32/winevt/Logs/`
- Active logs and archived `Archive-*.evtx` files copied by `windows_evtx_collection`

## Output

- Writes JSONL event records emitted by the vendored Artemis EVTX parser runtime.
- Merges all matched log sources into one family output and one family log.
- Preserves the existing Holo Forensics plan, manifest, and output naming contract.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover both active and archived EVTX logs.

## Update Checklist

- Update this page if EVTX discovery rules or collection binding change.
- Update this page if the vendored Artemis fork or emitted schema changes.
- Update this page if validation coverage changes.
