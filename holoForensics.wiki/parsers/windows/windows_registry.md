# windows_registry

## Summary

Native Rust offline parser for Windows Registry hives using `notatin`.

## Source

- `src/parsers/windows/windows_registry.rs`

## Inputs

- `NTUSER.DAT`
- `UsrClass.dat`
- `Amcache.hve`
- `SYSTEM`
- `SOFTWARE`
- `SAM`
- `SECURITY`
- `DEFAULT`
- `COMPONENTS`
- `settings.dat`
- `drvindex.dat`
- Adjacent `.LOG1` and `.LOG2` transaction logs when present

## Output

- Writes one JSONL record per registry key.
- Embeds a `values` array with parsed registry values under each key record.
- Emits analyst-facing path and mapping fields such as `registry_path`, `parent_key_path`, `hive_mapping`, `sid`, `hive_user_context`, and parser metadata.
- Writes a family log with per-hive counts plus transaction-log and recovery diagnostics.

## Validation

- `cargo test`
- Registry coverage should be verified with representative offline hives.

## Update Checklist

- Update this page if supported hive detection changes.
- Update this page if output schema or parser metadata changes.
- Update this page if transaction-log handling changes.
- Update this page if deleted-recovery behavior or performance characteristics change.

