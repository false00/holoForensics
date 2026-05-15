# windows_mplogs

## Summary

Native Rust parser for Microsoft Defender Support `MPLog*.log` artifacts.

The parser treats MPLogs as semi-structured text, preserves the raw line, detects UTF-8 and UTF-16LE input, extracts timestamps and timestamp assumptions, classifies high-level Defender event types, and emits normalized JSONL records with a stable `fields` map.

## Source

- `src/parsers/windows/mplogs.rs`

## Inputs

- `C/ProgramData/Microsoft/Windows Defender/Support/MPLog*.log` from `windows_mplogs_collection`
- Parser-only input is also accepted when the evidence package contains `MPLog*.log` files anywhere under the extracted root

## Output

- Writes one JSONL record per parsed MPLog line under the family output directory.
- Preserves the original line in `raw` and the trimmed event text in `message`.
- Emits normalized fields including:
  - `source_file`
  - `source_sha256`
  - `encoding`
  - `line_no`
  - `timestamp_raw`
  - `timestamp_utc`
  - `timestamp_assumption`
  - `component`
  - `level`
  - `event_type`
  - `threat_name`
  - `threat_id`
  - `path`
  - `process`
  - `action`
  - `result`
  - `hresult`
  - `fields`
- Writes a family log with per-file parse status, detected encoding, lossy-decode state, and record counts.

## Parsing Notes

- Detects UTF-8, UTF-8 BOM, UTF-16LE BOM, and UTF-16LE via a null-byte heuristic.
- Parses ISO-like and U.S.-style timestamps.
- Leaves `timestamp_utc` empty when the MPLog line does not declare a timezone and records `timestamp_assumption` as `local_time_unspecified`.
- Extracts best-effort key/value fields from both `key=value` and `key: value` fragments.
- Classifies common Defender categories including `Threat`, `Detection`, `Quarantine`, `Scan`, `Update`, `Engine`, `Platform`, `RealTimeProtection`, `CloudProtection`, `Exclusion`, `TamperProtection`, `Error`, `Warning`, `Info`, and `Unknown`.
- Keeps unusual or partially parsed lines instead of dropping them.

## Validation

- `cargo test --locked mplogs`
- Revalidate with a representative collected MPLog whenever line classification, key extraction, or timestamp handling changes.

## Update Checklist

- Update this page if MPLog input detection changes.
- Update this page if emitted fields, timestamp assumptions, or event classifications change.
- Update this page if the parser begins correlating MPLogs with additional Defender evidence such as Operational EVTX or Quarantine history.