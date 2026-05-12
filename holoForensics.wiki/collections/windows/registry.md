# windows_registry_collection

## Summary

Native Rust live collector for Windows Registry hives. The primary runtime uses a live VSS snapshot so the collector can preserve hive files, per-user hives, and adjacent transaction logs under their original Windows paths.

## Source

- `src/collections/windows/registry.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`

## Workflow

- Normalizes the selected NTFS source volume.
- Attempts to enable `SeBackupPrivilege` and `SeRestorePrivilege`.
- Creates a temporary native Windows VSS snapshot for the requested NTFS volume in standalone collector mode.
- Reuses the archive workflow's shared VSS snapshot when Registry is collected with USN, EVTX, MFT, `$LogFile`, INDX, SRUM, and/or Browser Artifacts for the same volume, so the collectors read the same point-in-time volume state.
- Copies system hives, user hives, service-profile hives, `Amcache.hve`, `BCD`, and adjacent transaction logs from the snapshot device path.
- Preserves the original Windows path inside the collected output tree and desktop package zip.
- Hashes every collected file with SHA-256.
- Writes a per-volume manifest plus collection log under the central collector metadata root `$metadata/collectors/<volume>/windows_registry/`.

Alternate mode:

- `--method reg-save` remains available as an explicit fallback when a logical hive export is preferred over VSS.

## CLI

```powershell
holo-forensics collect-registry --volume C: --out-dir C:\temp\registry --method vss-snapshot --elevate
```

## Output

- Preserved hive paths such as `C/Windows/System32/config/SYSTEM`
- Preserved hive paths such as `C/Windows/System32/config/SOFTWARE`
- Preserved hive paths such as `C/Windows/System32/config/DEFAULT`
- Preserved hive paths such as `C/Users/<user>/NTUSER.DAT`
- Preserved hive paths such as `C/Users/<user>/AppData/Local/Microsoft/Windows/USRCLASS.DAT`
- Preserved transaction logs such as `.LOG1`, `.LOG2`, `.blf`, and `.regtrans-ms`
- `$metadata/collectors/C/windows_registry/manifest.json`
- `$metadata/collectors/C/windows_registry/collection.log`

The registry manifest records the shadow-copy id, device path, context, create/delete state, and whether the snapshot was shared by the archive workflow.

## Validation

- `cargo test`
- `cargo run -- collect-registry --volume C: --out-dir target\registry-vss-smoke --method vss-snapshot --diagnostic-log target\registry-vss-smoke\diag.log --elevate`
- Desktop Collection tab packages registry hives through the same collector path when `Registry Hives` is selected.

## Update Checklist

- Update this page if the supported hive set changes.
- Update this page if the live collection method changes.
- Update this page if the manifest schema or archive layout changes.

