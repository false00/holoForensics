# windows_search_collection

## Summary

Catalog-only Windows collection contract for parsing Windows Search databases when raw evidence already exists inside an archive. Holo Forensics does not currently ship a Create Package collector for this contract.

## Source

- `src/collection_catalog.rs`
- Bound parser page: `holoForensics.wiki/parsers/windows/search.md`

## Accepted Inputs

- `Windows.edb`
- `Windows.db`
- Matching files can appear anywhere inside the supplied evidence package; Parse Mode discovers them by filename.

## Output Contract

- No live collector or desktop collection card is bound to this contract today.
- Parse Mode binds matching files to `windows_search`.

## Validation

- `cargo test --lib parser_catalog::tests::enabled_parser_families_use_descriptive_names -- --exact`
- Representative validation should cover Windows Search databases from supported Windows versions.

## Update Checklist

- Update this page if a live collector is added.
- Update this page if accepted filenames or parser binding change.
- Update this page if validation coverage changes.