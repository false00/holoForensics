# AGENTS

This file is the canonical assistant-facing instruction surface for this repository. Keep assistant-only workflow guidance here instead of in the public README or wiki.

## Architecture

- Preserve the current repository architecture unless the user explicitly asks for a structural change or a technical constraint makes the existing design unworkable.
- Keep new parser and collector work aligned with the current contract-driven layout across `src/parsers/`, `src/collections/`, `src/parser_catalog.rs`, `src/collection_catalog.rs`, `src/collection_metadata.rs`, the wiki, and the main README.
- Information from analysts, DFIR leads, or other forensic practitioners can refine parsing or collection behavior, but it should not trigger unsolicited architecture changes. If a structural change is technically required, keep it consistent with the existing design principles already used in this repo.

## Documentation Contract

- Treat documentation as part of the shipped runtime surface. Parser and collector changes are incomplete until the affected documentation is updated in the same change whenever possible.
- Keep the root `README.md` strictly user-facing. Do not add agent-only, maintainer-only, validation-only, or other non-user-facing workflow details there.
- When non-user-facing context, contributor commands, validation steps, or technical reference material needs documentation, update `holoForensics.wiki/Home.md` instead of expanding the root `README.md`.
- When a parser changes, update the matching page under `holoForensics.wiki/parsers/` and any affected parser index pages.
- When a collector or collection contract changes, update the matching page under `holoForensics.wiki/collections/` and any affected collection index pages.
- When a new parser, collector, or collection contract is added, create the corresponding wiki page if it does not exist and add it to the appropriate index.
- Update `README.md` whenever parser coverage, collection coverage, workflow, architecture, commands, output contracts, or documentation indexes change.

## Validation

- When changing Slint files, desktop UI layout, theming, or other user-visible UI behavior, validate the rendered result with `capture-ui-screenshots.ps1` before concluding the task.
- Prefer the narrowest screenshot state that covers the change, such as `about`, `settings`, `main`, `scope`, `usn-settings`, or `collection-progress`.
- Mention the captured screenshot path in the final response when UI validation was part of the work.
- When changing `src/parsers/windows/artemis.rs`, vendored Artemis schemas, or other Artemis-backed Windows parser plumbing, verify the exact current Artemis option-field names against the vendored structs and add or update a regression test that fails if the serialized config drifts. Serde can ignore unknown fields, so a wrong field name may silently fall back to live-host parsing instead of failing fast.
- For Artemis-backed Windows parser changes, run at least one parse-mode validation against a real collection zip or a focused repro archive. Verify emitted evidence paths stay rooted under the extracted evidence tree, and inspect nested parser logs as well as the manifest because manifest `ok` can still hide raw-drive fallback or zero-byte outputs.
- When accepting upstream dependency changes from vendored Artemis, explicitly check for root-workspace compatibility constraints such as BOA or ICU graph conflicts and `rusqlite` or SQLite linkage alignment before treating the bump as mechanical.

## Commit And Push

- If asked to run `git commit` or `git push`, first verify that any parser- or collection-related code changes also include the required wiki and README updates.
- Do not treat parser or collector module additions as ready to commit while the related catalog or documentation updates are still missing, unless the user explicitly asks to defer documentation work.
- Expect `.github/hooks/validate-git-doc-sync.ps1` through `.github/hooks/git-doc-sync.json` to enforce parser and collector doc sync before assistant-run commits and pushes.
- The same hook runs `cargo fmt --check` for Rust changes before assistant-run commits and pushes.
- The same hook runs `cargo test --locked` before assistant-run pushes that include code, build, or UI changes.
- If the hook blocks a commit or push, surface the failure reason, fix it locally, and retry instead of bypassing the guard.
- Before assistant-run pushes that include vendored dependency updates or large upstream fixture imports, scan the staged vendored tests and fixtures for credential-like literals or other secret-scanning tripwires. Replace obviously fake placeholders before retrying the push rather than treating the remote rejection as the first signal.

## Release Workflow

- When the user asks to release, increment the application version before committing. If the user does not specify a target version, advance to the next patch release.
- Prepare the release changelog in-repo so the published GitHub release body is explicit instead of relying only on generated notes.
- Draft release notes from the actual commit range since the previous release tag, not from memory or only the latest change. Compare the previous `vX.Y.Z` tag commit to the current unreleased state, review all commits in that range, and summarize the shipped changes from that history.
- If the upcoming release also includes local uncommitted changes, fold those pending changes into the draft release notes before committing so the final tag reflects the full shipped delta from the previous release.
- If the user asks to review the release copy before publishing, stop after drafting the version bump and changelog and wait for approval before any push.
- Once the release is approved, commit the release changes, push `main`, create or update the matching `vX.Y.Z` git tag, and push that tag so the release workflow publishes the release.
- Treat an explicit user request to release as approval to perform the required commit, `main` push, and release-tag push sequence after any requested review checkpoint is complete.
