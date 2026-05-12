# windows_browser_artifacts_collection

## Summary

Native Rust live collector for Windows browser artifact acquisition. The collector uses a VSS snapshot, copies a targeted standard IR browser artifact set from the snapshot rather than live paths, and includes DPAPI plus registry support material needed for later encrypted-data parsing.

## Source

- `src/collections/windows/browser_artifacts.rs`
- Shared metadata path helper: `src/collection_metadata.rs`
- Shared VSS lifecycle helper: `src/collections/windows/vss.rs`
- Shared archive workflow: `src/app.rs`

## Mode

- `vss`: default and only current acquisition mode. Creates or reuses a native Windows VSS snapshot, copies targeted browser and support files from the point-in-time snapshot, hashes source and destination bytes, and records copy failures honestly.

## CLI

```powershell
holo-forensics collect-browser-artifacts --volume C: --out-dir C:\temp\browser --elevate
```

## Workflow

- Normalizes the selected volume.
- Attempts to enable `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege`.
- Creates a native Windows VSS snapshot through the shared Rust VSS helper; no PowerShell or `vssadmin` path is used.
- In archive collection, reuses the shared VSS snapshot when Browser Artifacts are collected with Registry, EVTX, SRUM, Jump Lists, LNK Files, `$MFT`, `$LogFile`, INDX, or USN for the same volume.
- Enumerates `C:\Users\*` from the snapshot and copies targeted Chromium artifacts when present:
  - User Data root files: `Local State`, `First Run`, `Last Version`
  - Profile databases and sidecars: `History*`, `Archived History*`, `Network\Cookies*`, `Cookies*`, `Web Data*`, `Login Data*`, `Bookmarks*`, `Preferences`, `Secure Preferences`, `Favicons*`, `Top Sites*`, `Shortcuts*`, `Visited Links`, `Network Action Predictor*`, `Network Persistent State*`, `Reporting and NEL*`, `TransportSecurity*`, `Trust Tokens*`, `DIPS*`, and `QuotaManager*`
  - Profile directories: `Sessions\`, `Local Storage\`, `Session Storage\`, `IndexedDB\`, `File System\`, `Storage\`, `databases\`, `Service Worker\`, `Extension State\`, `Local Extension Settings\`, and `Sync Extension Settings\`
  - Extension package metadata only: `Extensions\*\*\manifest.json`
- Recursively copies supported non-Chromium browser roots when present:
  - `AppData\Roaming\Mozilla\Firefox\`
  - `AppData\Local\Mozilla\Firefox\`
  - `AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\`
  - `AppData\Local\Microsoft\Windows\WebCache\`
  - `AppData\Local\Microsoft\Windows\INetCache\`
  - `AppData\Local\Microsoft\Windows\INetCookies\`
- Copies per-user support material:
  - `AppData\Roaming\Microsoft\Protect\`
  - `AppData\Roaming\Microsoft\Credentials\`
  - `AppData\Local\Microsoft\Credentials\`
  - `NTUSER.DAT`
  - `ntuser.dat.LOG*`
- Copies system support material:
  - `C:\Windows\System32\config\SYSTEM`
  - `C:\Windows\System32\config\SECURITY`
  - `C:\Windows\System32\config\SOFTWARE`
  - `C:\Windows\System32\Microsoft\Protect\`
- Skips reparse/symlink paths to avoid recursion loops and records those skips as warnings.
- Computes SHA-256 for each VSS source and copied destination file.
- Verifies source and destination hashes match.
- Records file metadata, copied files, warnings, and failures in the centralized manifest.
- Deletes owned VSS snapshots after collection.

## Output

- `C/Users/*/AppData/Local/Google/Chrome/User Data/Local State`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/History*`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Archived History*`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Network/Cookies*`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Cookies*`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Web Data*`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Login Data*`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Bookmarks*`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Preferences`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Secure Preferences`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Favicons*`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Top Sites*`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Shortcuts*`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Visited Links`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Sessions/**`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Local Storage/**`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Session Storage/**`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/IndexedDB/**`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/File System/**`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Storage/**`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/databases/**`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Service Worker/**`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Extensions/*/*/manifest.json`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Extension State/**`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Local Extension Settings/**`
- `C/Users/*/AppData/Local/Google/Chrome/User Data/*/Sync Extension Settings/**`
- Equivalent targeted paths under `C/Users/*/AppData/Local/Microsoft/Edge/User Data/`
- `C/Users/*/AppData/Roaming/Mozilla/Firefox/**`
- `C/Users/*/AppData/Local/Mozilla/Firefox/**`
- `C/Users/*/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/**`
- `C/Users/*/AppData/Local/Microsoft/Windows/WebCache/**`
- `C/Users/*/AppData/Local/Microsoft/Windows/INetCache/**`
- `C/Users/*/AppData/Local/Microsoft/Windows/INetCookies/**`
- `C/Users/*/AppData/Roaming/Microsoft/Protect/**`
- `C/Users/*/AppData/Roaming/Microsoft/Credentials/**`
- `C/Users/*/AppData/Local/Microsoft/Credentials/**`
- `C/Users/*/NTUSER.DAT`
- `C/Users/*/ntuser.dat.LOG*`
- `C/Windows/System32/config/SYSTEM`
- `C/Windows/System32/config/SECURITY`
- `C/Windows/System32/config/SOFTWARE`
- `C/Windows/System32/Microsoft/Protect/**`
- `$metadata/collectors/C/windows_browser_artifacts/manifest.json`
- `$metadata/collectors/C/windows_browser_artifacts/collection.log`

The manifest uses schema `windows_browser_artifacts_collection_v1` and records source root, source globs, VSS metadata when used, enabled privileges, copied file metadata, SHA-256 values, failures, and warnings.

## Current Scope

- Browser acquisition is implemented through VSS targeted file copy.
- Chrome and Edge use a Tier 2 / standard IR target set rather than full `User Data` tree collection.
- Extension package directories are not copied wholesale; only `Extensions\*\*\manifest.json` plus extension storage directories are included by default.
- SQLite sidecars such as `-wal`, `-shm`, and `-journal` are included for targeted databases when present.
- No browser parsing is performed during collection.
- The active Windows browser history parser now binds to this collection contract.

## Validation

- `cargo test browser_artifacts`
- `cargo test`
- Desktop Collection tab packages Browser Artifacts through the same collector path when `Browser Artifacts` is selected.

## Update Checklist

- Update this page if supported browser roots, targeted file patterns, or DPAPI/support paths change.
- Update this page if targeted or browser-specific collection modes are added.
- Update this page if the manifest schema or archive layout changes.
