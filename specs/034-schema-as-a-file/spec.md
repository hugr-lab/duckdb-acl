# Spec 034: the policy schema is a file

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

The managed schema lived as a 132-line C++ string literal that only the extension could run. It is
now `schema/policy_schema.sql`, and both the C++ constants and a file an operator can apply by hand
are rendered from it. One source, so a hand-applied schema and the one `acl_use_db` creates cannot
say different things. The migration replay it used to carry is gone with it: there is no release, so
there is no catalog to migrate — what migrations must do when there is one is written down instead.

## Problem

Spec 033 established that the catalog can live in a foreign database, and that getting it there takes
care. What it could not offer was a way to *look* at the schema, or to create it yourself: the DDL
existed only as a `vector<string>` in `InitSchema`, and reading it meant reading C++ string
concatenation. An operator who wanted the schema in their own database — under their own migration
tooling, with their own grants, in a database the gateway may only read — had to transcribe it.

The literal had also fossilised. Its `CREATE TABLE`s were the *original* shape of each table, and the
15 later columns arrived as `ALTER TABLE … ADD COLUMN` — the migration history, replayed on every
init. Nothing was wrong with it, but the answer to "what does `relations` look like?" was spread over
four places in the list.

## Design

**`schema/policy_schema.sql` is the source of truth**, in duckdb dialect, with three placeholders:
`<schema>` and `<table>` for the names of the catalog being initialised, and `ACL_KEY_TEXT` for the
type of a key column — the one thing that genuinely differs per target (spec 033).

**The schema is the tables as they are *now***: one complete `CREATE TABLE` each, every column
present, and the version stamped into `meta` at the end. The 15 `ALTER TABLE … ADD COLUMN` statements
that used to replay the history on every init are gone — duckdb-acl has not been released, so no
catalog exists that needs migrating from an older shape.

**Migrations get a contract rather than an implementation**, in `schema/migrations/README.md`: one
`v<n>.sql` per version step, applied when the catalog's own `meta.schema_version` is lower, each
ending with its own stamp — and the invariant that a catalog migrated to `<n>` and one created fresh
at `<n>` must be identical. Nothing implements the loader yet, because there is nothing for it to
load; writing it now would be untested machinery guarding an empty directory.

That replaces the shape the extension used to have — replay every `ALTER … IF NOT EXISTS` forever —
which grows without bound and is not portable: the SQL Server scanner drops the clause, which is what
spec 033 had to work around. A version the catalog carries is cheaper and works everywhere.

**`scripts/gen_schema.py` renders it** into `src/acl_schema_sql.hpp` (placeholders intact —
what `InitSchema` runs) and `schema/acl_schema.sql` (names resolved, ready to run). `make schema`
regenerates; `make schema-check` fails when they are stale.

**The version is a decision, not a comparison in SQL.** The stamp read `WHERE "value" < '10'` —
string order, in which `'9' < '10'` is false, so a catalog at 9 would never be re-stamped and no
migration would ever pick it up. Casting it in SQL fixes the ordering and breaks something else: a
stamp that is not a number *throws*, leaving a corrupt catalog impossible to re-initialise. The
schema file only ever inserts the stamp; bringing an existing one up to date happens in C++, where
"unreadable" is a case rather than an exception.

**A catalog says which shape it is, and a build refuses one it does not read.** `schema_version` was
reported by `acl_status()` and checked by nothing, so applying the wrong version's file surfaced as a
missing column in the middle of somebody's query. `acl_use_db` now refuses it by name, with both
numbers — the failure a hand-applied schema makes possible is the one worth catching early.

**Only the duckdb dialect is rendered.** A hand-rolled per-dialect renderer — T-SQL batch guards,
`IF OBJECT_ID`, type maps — is a second thing to keep correct, and the schema is plain SQL that a
real translator handles. Both generated files say what a target may need to change instead.

**`make schema-check` applies the file** to an empty database and then points the extension at it with
init disabled, so the check is not "do the bytes match" but "does the extension accept what an
operator would have created". A policy is written and read through it; the RLS predicate has to
narrow two rows to one.

## Enforcement & security

- **The schema did not change**, only where it is written. The statements the extension runs are the
  same ones, in the same order — the full non-integration suite and the integration suite (including
  the SQL Server catalog) pass unchanged.
- **A hand-applied schema is not a weaker one.** `acl_use_db(db, schema, false)` was already the
  supported way to use an existing schema; this only makes the schema available to apply. Whoever
  applies it owns the grants on those tables, which is the point: the policy catalog can now live in a
  database the gateway is not allowed to create tables in.
- **The check is the guarantee.** Without `make schema-check` in the loop the two would drift the
  first time someone edits one and not the other, and a drifted policy schema fails at a query rather
  than at init.

## Testing

`make schema-check`: the rendered files regenerate byte-identically, and `schema/acl_schema.sql`
applied to an empty database serves a real policy with init disabled.

`test/sql/acl_schema_version.test` (23 assertions): a stamp from another version refused with both
numbers, a missing one and an unreadable one each refused by their own reason, `acl_use_db(…, true)`
making any of them current again rather than refusing, and the check happening where the catalog is
chosen rather than in the middle of a query.

The behaviour of the schema itself is covered where it always was — every catalog-backed test
initialises it, so the whole suite is the regression test for the rendering being faithful. Both
suites pass unchanged: 36 files locally, 132 assertions over 6 integration scenarios.

## Alternatives considered

- **Render each dialect ourselves.** Written and then removed: it needs T-SQL batch guards, an
  `IF OBJECT_ID` wrapper per table and a type map per engine, all of it exercised by nothing. The SQL
  is simple enough that a translator does a better job than a renderer we maintain.
- **Keep the C++ as the source and dump SQL from it.** The direction that suggests itself, and the
  wrong one: the artifact an operator applies would be generated from a form nobody applies, so the
  thing under review would be the copy rather than the original.
- **Generate the header at build time.** It adds a Python dependency to a plain `make`. The generated
  header is committed instead, and `schema-check` is what catches a stale one.
- **Keep the migrations and make them version-driven now.** The mechanism is worth having and the
  files are not: with no release there is no catalog below the current version, so the loader would
  be exercised by nothing. The contract is written down instead, which is the part that is hard to
  change later.

## Addendum 2026-09-03 — v13, and the migration contract is checked rather than promised

Schema **13** (`schema/migrations/v13.sql`): the pre-spec-015 `schema_aliases` table goes. It had been
"kept in step for one version, so a rollback still resolves" after `schemas` replaced it — written on
every schema write, read by nothing in table mode (the function-driver *slot* of that name is a
callback contract and stays) — and no release ever shipped it, so there was no version to roll back
to. The migrations README claimed the steps were generated (`gen_schema.py` never did; v11–v13 are
hand-written) and promised an invariant nothing verified: a catalog migrated from n−1 and one created
fresh at n have the same columns in the same order. `make schema-check` now proves it — a catalog is
built from the schema file `origin/main` ships, every step above its version is applied, and the
column shape of every `acl` table (name, position, type) plus the stamp is diffed against a fresh
catalog; before a merge that is the new step under test, after it both sides are n and it says so.
CI runs it on every PR (phase 0 of the release plan).

## Follow-ups

- **The first release needs the loader.** `schema/migrations/README.md` says what it must do; until
  something implements it, a catalog below the current version is not upgraded — which is safe only
  while no such catalog exists.
- Removing the replay took a scenario with it: `acl_virtual_schemas.test` covered a pre-v4 catalog
  whose schema aliases were backfilled into `schemas` on init. That capability is gone, deliberately —
  it can only matter to a catalog created before a release that has not happened.
- The version stayed at 10 rather than resetting to 1. It is the tenth shape this schema has had, and
  the catalogs that exist say 10; the first release is the moment to decide whether that number is
  the one to ship.
- `make schema-check` needs a built `duckdb` binary for its second half. In CI that is free; locally
  it means the check is only as current as the last build.
- Nothing yet renders the schema for a *specific* schema name other than `acl` — an operator changing
  it edits the generated file, which the header of that file tells them not to do. A parameter would
  be better than the note.
