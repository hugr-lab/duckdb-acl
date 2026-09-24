# Spec 087: the docs site

- **Status**: implemented
- **Date**: 2026-09-24
- **Release plan**: phase 5.1 (documentation before release)
- **Mirrors**: the sites of tresor, mssql-extension and mssql-ducklake, and the org site
  hugr-lab.github.io

## Problem

The user documentation (about 3300 lines: serving, authentication, management SQL, the policy
catalog, security, observability, deployment, clients) lived in `docs/` and was readable only on
GitHub. There was no getting-started page, no page that states the model, and no published site. The
sibling repositories already publish Docusaurus sites with one look.

## Design

- **Source.** `website/` is a Docusaurus 3 site scaffolded from tresor's: the same packages, CSS,
  logos, navbar and footer shape.
- **Pages.** `website/docs/*.md` are now the user docs. `git mv` moved them from `docs/`, so their
  history follows. The site adds three pages:
  - `getting-started.md`: from an empty DuckDB to a principal reading a row-filtered table, then a
    door. Its SQL was run against the build as written.
  - `concepts.md`: two ways in, virtual catalogs, grants and capabilities, the function gate,
    administration, sessions.
  - `development.md`: build, test, specs, and the docs themselves.
- **What stays in `docs/`.** Developer-only notes (`vcpkg-cache-r2.md`, the template's
  `UPDATING.md`).
- **Markdown format.** `markdown.format: 'detect'` makes `.md` CommonMark, not MDX. The pages are
  full of `<role>` and `{"caps": …}`, which MDX would parse as JSX.
- **Links.** A link to a repository file (`../specs/…`, `../schema/…`, `../CLAUDE.md`) became a GitHub
  URL. A link between pages stays relative.
  - `onBrokenLinks` and `onBrokenAnchors` are set to `throw`. They caught a directory link and an
    anchor that lacked its heading's `(spec 068)`.
  - `scripts/ci/check_docs_links.py` (tresor's) refuses absolute site paths, which would escape a
    docs version.
- **Workflows, as tresor's.**
  - `docs-build.yml` builds on PRs that touch `website/`.
  - `pages.yml` deploys `main` to https://hugr-lab.github.io/duckdb-acl/. The docs version of each
    release tag is snapshotted at deploy time, so the latest release serves at the root and `main`
    under `/next/`.
- **References.** Every reference to `docs/<page>.md` in the repository (CLAUDE.md, specs, sources,
  tests, the runbook) now points at `website/docs/`. The README links the site and loses two stale
  claims: that there are no migrations, and that the gateway is only planned.

## Enforcement & security

Documentation only.

## Tests

- `npx docusaurus build` succeeds, with broken links and anchors failing the build.
- `check_docs_links.py` passes.
- The getting-started SQL ran as written: the principal sees only its tenant's row, the physical name
  is refused, and the issuer is created.

## Follow-ups

- **Pages.** GitHub Pages must be enabled for the repository (source: GitHub Actions) before the first
  deploy. That is the owner's switch.
- **Workflows.** The two workflow files need a push with the `workflow` scope (see the repository's
  note on gh tokens).
