# Spec 094: the schema compatibility window - rolling upgrades across a catalog schema change

- **Status**: implemented
- **Date**: 2026-09-30
- **Design**: design/017-hugr-platform §3.2a (a node never migrates the shared catalog by itself)

## Summary

A policy catalog now says not only which schema version it is (`schema_version`) but also the oldest
build that may still read it (`min_reader_version`). A build newer than the catalog refuses and says
how to migrate. A build older than the catalog but inside its window **serves from it and never
writes**. A build below the window refuses. The build embeds its migration steps and applies them
with `acl_migrate_catalog(db[, schema])` in one transaction.

This makes a rolling upgrade across a schema change possible: migrate first, the old nodes keep
serving, then roll them.

## Problem

A node required exact equality between the catalog's `schema_version` and its build
(`RequireSchemaVersion`). It never migrated the shared catalog itself; an operator applied
`schema/migrations/v<n>.sql` by hand. In a fleet that makes every schema change a stop-the-world
switch-over:
- after the migration no old node reads the catalog;
- before it, no new node does.

A running old node did not even notice a migrated catalog. It kept reading, and its policy writes
(whole-row rewrites) would drop what the new step added.

## Design

- **The window is declared per step.** Each migration file states `-- min_reader: <n>` in its header.
  - `make schema` refuses a step without it, and one declaring more than its own version.
  - `policy_schema.sql` stamps `min_reader_version` for a fresh catalog, and it must equal the latest
    step's. `make schema` checks the two.
  - The number is the author's judgment: can an older build that ignores what the step adds ever
    admit more? A new restriction (a column that narrows access) cannot keep older readers.
  - Shipped: v16 (the cluster profile's tables, spec 093) declares 15. Every earlier step is strict.
- **The build judges a stamp** (`CatalogBackend::JudgeSchema`):

  | catalog | verdict |
  | --- | --- |
  | this build's version | current |
  | newer and `min_reader_version ≤ build` | read-only: `compat_read_only` |
  | newer and outside the window | refused: *"… readable from build N on, and this build is M - upgrade the node"* |
  | older | refused: *"… migrate it first: SELECT acl_migrate_catalog('db', 'schema') on a node of this build"* |

  A catalog from before this spec, with no `min_reader_version`, is read as a window of exactly its
  own version.
- **Where the stamp is judged.**
  - At open (`RequireSchemaVersion`) and at init (`InitSchema`, which no longer replays DDL over a
    newer catalog inside the window).
  - **At every freshness check** (`EnsureFresh`, table mode, together with `policy_version`). A
    catalog migrated under a running node moves that node into read-only mode, or out of service, at
    its next check. The refusal is fail-closed and counted as a `source_error`, like an unreachable
    source.
- **Writes check inside their transaction.** `Write` and `WriteWithReads` read `schema_version` in
  the write's own transaction and refuse unless it is exactly this build's. That also closes the race
  where a migration lands between a check and a write.
- **`acl_migrate_catalog(db[, schema])`** (schema defaults to `acl`):
  - reads the stamp, then applies every embedded step above it, in order, in one transaction, setting
    `min_reader_version` after each step;
  - checks that the result is stamped with this build's version, commits, and answers *"… migrated
    from schema version 15 to 16 (readable from build 15 on)"*;
  - is idempotent (*"already schema version 16"*);
  - refuses a newer catalog, a gap (a catalog older than the build's first step: *"carries no step
    from schema version 9 to 10 - migrate with an older build first"*), and a database that is not an
    acl schema.

  If the store's own catalog is the one migrated, its next statement re-reads the stamp.
- **`acl_catalog_schema()`** reports `{build, build_min_reader, catalog, min_reader, mode}`, where mode
  is `current`, `read_only`, `refused` or `none`.
- The steps are embedded by `make schema`: `ACL_SCHEMA_STEPS` in `src/acl_schema_sql.hpp`, with names
  turned back into placeholders (`acl."meta"` → `<meta>`) so a step applies to any database and
  schema. The files stay the source.

## Enforcement & security

- **A read-only node serves only the policy it can read.** The window is the author's statement that
  ignoring the newer step admits nothing more. A step that could widen access by being ignored must
  declare itself strict, which turns old nodes off at their next check (fail closed, never open).
- **An old node never writes into a newer catalog**, checked inside the write's transaction.
- **Migration is never automatic.** A node never migrates the shared catalog by itself (design/017
  §3.2a); the orchestrator or an operator calls `acl_migrate_catalog`. Like every `acl_*` function it
  is denied to a principal.

## Testing

- **`test/sql/acl_schema_window.test`** (41 assertions):
  - current mode;
  - a catalog stamped newer inside its window, under the running node: reads still served, mode
    `read_only`, policy writes and cluster writes refused, and nothing written;
  - outside the window: the running node refuses (fail closed), and `acl_use_db` refuses at open;
  - `acl_migrate_catalog` refuses a newer catalog;
  - an older catalog (a v16 catalog made v15 by removing what v16 added):
    - `acl_use_db` refuses with the migrate hint, with and without init;
    - `acl_migrate_catalog` migrates it and answers what it did, then is idempotent;
    - the migrated catalog serves and writes, and v16's tables work;
  - not an acl schema: refused.
- **`test/sql/acl_schema_version.test`**: the new refusal wording, and a v9 catalog refused by
  `acl_migrate_catalog` for its gap. **`acl_declared_shape.test`**: the init refusal wording.
- **`make schema-check`**: a catalog migrated from `origin/main`'s schema by the files matches a fresh
  one (15 → 16), and the hand-applied schema works.

## Alternatives considered

- **Nodes migrate the catalog on open.** Rejected: the first new node to start would change the
  shared catalog under every old node, with no operator decision (design/017 §3.2a).
- **An old node keeps writing into a newer catalog.** Rejected: its whole-row rewrites drop the newer
  columns' values.
- **Blue/green pools on a copied catalog.** Possible for strict steps. The window avoids it for the
  common case of a step that only adds.

## Follow-ups

- **SQL Server catalogs.** The embedded steps are the duckdb dialect, like the files. A step that
  creates a key column declares it `VARCHAR`, which SQL Server cannot index (spec 033). There,
  `acl_migrate_catalog` fails the step and rolls the whole migration back, so no half-migrated
  catalog is left. Such a catalog is migrated by hand, as before. Rendering steps with `ACL_KEY_TEXT`,
  as the schema already is, would remove this limit.
