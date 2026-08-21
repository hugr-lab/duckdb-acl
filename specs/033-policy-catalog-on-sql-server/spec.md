# Spec 033: the policy catalog on SQL Server

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

Spec 006 says the policy catalog may live in any ATTACHed database, in "standard duckdb dialect only,
source agnostic". SQL Server was the first source to test that claim, and it failed three times —
twice on a type the scanner produces, once on SQL we generate. All three are fixed, and the catalog
now runs there: schema init, policy writes, resolution and enforcement, twice in a row.

## Problem

`hugr-lab/mssql-extension` has migrated to duckdb main, so the pin could move from a stale commit to
that repo's `main` (`1d74ae2c`). With the scanner building, `acl_sqlserver.test` — enforcement over
live SQL Server data — passed unchanged, 24 assertions. Putting the *catalog itself* there did not:

1. **`acl_use_db` failed at the first `CREATE TABLE`**, with `SQL Server error 1750: Could not create
   constraint or index`. Every column of the policy schema is a duckdb `VARCHAR`, and the scanner
   creates all of them as `NVARCHAR(MAX)` — which SQL Server refuses to index, so no `PRIMARY KEY`
   could be built. Declaring a length does not help: `VARCHAR(128)` also lands as `nvarchar(-1)`,
   verified by reading `sys.columns` after the create.
2. **A second `acl_use_db` failed**, with `error 2705: Column names in each table must be unique`.
   The scanner drops the guard on `ALTER TABLE … ADD COLUMN IF NOT EXISTS`, so re-running the
   migrations tried to add a column that was already there.
3. **Resolution failed**, with `error 4145: An expression of non-boolean type specified in a context
   where a condition is expected, near 'is_main'`. T-SQL has no boolean type, so a `BIT` column
   cannot stand as a condition on its own — and the resolver pushes `WHERE … g."is_main"` down.

A fourth problem was not SQL Server's: `make docker-up` ran `docker compose` with no `-p`, so the
project name came from the compose file's directory — `docker`. Any other compose file living in a
directory of that name shares the project, and compose then treats its containers as ours. It
removed two unrelated containers on the developer's machine, and later removed *our* SQL Server
mid-run.

## Design

**Key columns are declared by the kind of catalog they live in.** `KeyColumnType()` asks
`duckdb_databases()` what the attached catalog is; for `mssql` it returns the scanner's own bounded
type, `MSSQL_VARCHAR(255)`, which lands as a real `varchar(255)` and indexes. Everywhere else it is
`VARCHAR`, unchanged. The DDL is written with a marker (`ACL_KEY_TEXT`) on the 47 columns that
participate in a primary key and substituted once, so the two dialects cannot drift apart.

This is the one place the schema is not dialect-agnostic, and it is narrow on purpose: a *type* for
key columns, not a per-source DDL path. `CREATE TABLE IF NOT EXISTS` means an existing catalog keeps
the columns it has.

**Migrations do not rely on `IF NOT EXISTS` being honoured.** Before running the `ALTER TABLE … ADD
COLUMN` statements, the schema init asks the catalog which columns it already has and skips those.
That is a property worth having whatever the backend does with the clause — a migration that is
idempotent only because one dialect implements a hint is idempotent by luck.

**A stored boolean is compared, not asserted.** The six places that pushed `g."is_main"` down as a
bare condition now write `g."is_main" = true`. A *computed* boolean (`(SELECT unique_main FROM
main_ok)`) needs nothing: duckdb evaluates it locally and it never reaches the source.

**The compose project has a name.** `name: duckdb-acl` in the compose file and `-p duckdb-acl` in the
Makefile, so no invocation can adopt an unrelated project's containers — in either direction.

## Enforcement & security

- **Nothing about the policy model changed.** The three fixes are about how the schema is written and
  how a query is spelled; what a grant means, and what it enforces, is untouched — the whole
  non-integration suite passes unchanged.
- **255 characters is a real limit on SQL Server** for a catalog name, an object name, a role, a
  schema path or an issuer: the columns that carry them are indexed there. Everywhere else they stay
  unbounded. A longer name is refused by SQL Server rather than silently truncated.
- **A boolean comparison is not a policy decision**, so `= true` cannot change who sees what: the
  column is written by the ACL itself and is never NULL for a row that exists.

## Testing

`test/sql/integration/acl_catalog_sqlserver.test` runs instead of skipping: the policy catalog is
created in SQL Server through the scanner, policy is written into it, and enforcement over the SQL
Server fixture resolves from it — 22 assertions. `acl_sqlserver.test` (enforcement over SQL Server
data, 24 assertions) was already correct and needed no change.

The full integration suite passes twice in a row — 132 assertions over 6 scenarios (MySQL still skips
at the duckdb pin) — which is what proves the migration idempotence rather than a single green run.

## Alternatives considered

- **Drop the primary keys.** They are load-bearing: sources without rowids need one for
  `DELETE`/`UPDATE`, and `INSERT OR IGNORE` (the expansion tombstones) has nothing to ignore on
  without a constraint.
- **Bound every column, not just the keys.** A view's SQL, a predicate and a claim map have no
  natural length, and truncating one silently would be a policy change. Only key columns are indexed,
  so only they need a bound.
- **Fix the type mapping in the scanner** so `VARCHAR(n)` survives as `NVARCHAR(n)`. That is the
  better long-term fix and it is in another repo; `MSSQL_VARCHAR` exists precisely so a caller can be
  explicit, so this uses it.
- **Keep `IF NOT EXISTS` and special-case SQL Server.** The check we now do is cheaper to reason about
  and correct everywhere, rather than correct on the dialects that implement a hint.

## Follow-ups

- MySQL is still skipped: `mysql_scanner` is disabled at the duckdb submodule pin ("patches do not
  apply"). Nothing here is MySQL-specific, but the same three classes of problem are worth re-testing
  when it comes back — MySQL also has no boolean type.
- `container_name:` is fixed in the compose file, so two projects can still collide over a container
  *name* even with distinct project names. Dropping it would let compose name containers per project;
  it would also change the names in every runbook.
- The 255 for key columns is a guess at a generous bound, not a measured one. If a deployment needs
  longer names on SQL Server, it is one constant.
