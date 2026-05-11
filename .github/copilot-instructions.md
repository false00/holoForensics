# Project Guidelines

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

- If the user asks to commit or push changes, first verify that any parser- or collection-related code changes also include the required wiki and README updates.
- Do not treat parser or collector module additions as ready to commit while the related catalog or documentation updates are still missing, unless the user explicitly asks to defer documentation work.