# Spec 025: DESCRIBE, SUMMARIZE and SHOW TABLES under a principal

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

`DESCRIBE`, `SUMMARIZE` and `SHOW TABLES` were refused by the statement gate. They are the forms a
client sends *before* it sends anything else, so refusing them left ordinary tools — and agents —
talking to a wall. They are answered now, from the principal's own catalog.

## Problem

The rewriter walks table references and refused any form it did not recognise, which included
DuckDB's `ShowRef` — the node behind `DESCRIBE t`, `SUMMARIZE t`, `SHOW TABLES` and
`SHOW TABLES FROM s`. A BI tool describing a table, or an agent asking what exists before writing a
query, got `table reference form is not permitted under ACL`.

Answering them cannot mean handing the statement to DuckDB with a physical name substituted in: a
`DESCRIBE` of the physical table lists columns a projection hides.

## Design

**`DESCRIBE <name>` becomes `DESCRIBE (SELECT * FROM <name>)`.** `ShowRef` already carries either a
name or a query, and both produce the same shape for the caller. Replacing the name with a query over
the same virtual relation sends the answer through the ordinary read path: the projection, the
renames, the grant's column list all apply, and the description is of what the principal can read.
Nothing about `DESCRIBE`'s output had to be reimplemented.

**`SUMMARIZE` is the same substitution.** It reads data, so it goes through the same path and the
grant's predicate applies to what it summarises — a role that may read one row of two summarises one.

**`DESCRIBE (SELECT …)`** needs nothing new: the query inside is rewritten like any other.

**`SHOW TABLES` is a listing, so it is answered by the listing.** The `ShowRef` is replaced with a
subquery over the principal's `information_schema.tables` (spec 010), projected to the single `name`
column `SHOW TABLES` returns. A bare `SHOW TABLES` is the default schema, as it is in DuckDB;
`SHOW TABLES FROM <schema>` filters to that schema, and to that catalog when one is written.

## Enforcement & security

- **A description is a read.** `DESCRIBE` of a name the principal has no grant on is refused by the
  same resolution as a `SELECT` from it, and a physical name is refused as a physical name always is.
  The test asserts both.
- **A hidden column is hidden from the description too**, because the description is of the rewritten
  relation rather than of the physical table.
- **`SUMMARIZE` returns aggregates of data**, so it is bounded by the grant's predicate rather than by
  the shape of the table. A role that may read nothing summarises nothing.
- Nothing here widens what may be read; it makes an existing right answerable in the form clients ask
  it in.

## Testing

`test/sql/acl_show_describe.test` (36 assertions): `DESCRIBE` of a projected relation showing the two
visible columns and neither hidden one; `DESCRIBE (SELECT …)`; the physical name and an ungranted name
each refused; `SHOW TABLES` and `SHOW TABLES FROM <virtual schema>` listing the principal's own
objects and nothing physical; `SUMMARIZE` counting only the rows the predicate allows while the table
holds more; and a role granted nothing listing nothing and being refused a description.

## Alternatives considered

- **Substitute the physical name into the `ShowRef`** and let DuckDB describe it. One line, and it
  lists every column the projection hides.
- **Reimplement `DESCRIBE`'s output** over `information_schema.columns`. It would answer, but it would
  drift from DuckDB's shape the first time that shape changed, and it would have to synthesise types
  for computed columns that the read path already knows.

## Follow-ups

- **`SHOW ALL TABLES`** has a wider shape (database, schema, name, column names and types) and is not
  handled yet; it maps onto the same listing.
- **`PRAGMA table_info` / `PRAGMA show_tables`** are statement forms rather than table references, so
  they are still refused by the statement gate; the same substitutions would answer them.
- **`SHOW DATABASES` / `SHOW SCHEMAS`** map onto the `databases` and `schemata` surfaces that spec 010
  already generates.
