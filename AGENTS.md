# AGENTS

This file is the canonical assistant-facing instruction surface for this repository. Keep assistant-only workflow guidance here instead of in the public README or wiki.

## Architecture

- Preserve the current repository architecture unless the user explicitly asks for a structural change or a technical constraint makes the existing design unworkable.
- Keep new parser and collector work aligned with the current contract-driven layout across `src/parsers/`, `src/collections/`, `src/parser_catalog.rs`, `src/collection_catalog.rs`, `src/collection_metadata.rs`, the wiki, and the main README.
- Information from analysts, DFIR leads, or other forensic practitioners can refine parsing or collection behavior, but it should not trigger unsolicited architecture changes. If a structural change is technically required, keep it consistent with the existing design principles already used in this repo.

## Documentation Contract

- Treat documentation as part of the shipped runtime surface. Parser and collector changes are incomplete until the affected documentation is updated in the same change whenever possible.
- When a parser changes, update the matching page under `holoForensics.wiki/parsers/` and any affected parser index pages.
- When a collector or collection contract changes, update the matching page under `holoForensics.wiki/collections/` and any affected collection index pages.
- When a new parser, collector, or collection contract is added, create the corresponding wiki page if it does not exist and add it to the appropriate index.
- Update `README.md` whenever parser coverage, collection coverage, workflow, architecture, commands, output contracts, or documentation indexes change.

## Commit And Push

- If asked to run `git commit` or `git push`, first verify that any parser- or collection-related code changes also include the required wiki and README updates.
- Do not treat parser or collector module additions as ready to commit while the related catalog or documentation updates are still missing, unless the user explicitly asks to defer documentation work.
- Expect `.github/hooks/validate-git-doc-sync.ps1` through `.github/hooks/git-doc-sync.json` to enforce parser and collector doc sync before assistant-run commits and pushes.
- The same hook runs `cargo fmt --check` for Rust changes before assistant-run commits and pushes.
- The same hook runs `cargo test --locked` before assistant-run pushes that include code, build, or UI changes.
- If the hook blocks a commit or push, surface the failure reason, fix it locally, and retry instead of bypassing the guard.
