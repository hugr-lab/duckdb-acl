# Spec 143: comments reach Flight clients in the Arrow schema

- **Status**: draft
- **Date**: 2026-10-22
- **Author**: hugr lab (the owner, 2026-10-19 and 2026-10-22: "описания колонок и объекта должны быть и должны быть видны
  в Arrow"; result schemas with their names; a virtual column comment, else the physical one; quack later)

## Summary

The virtual catalog's descriptions - an object's comment, its columns' - are in the SQL listings today, and nowhere in
what a Flight client reads as Arrow. This spec puts them there: GetTables' `include_schema` carries each column's
comment under Flight SQL's own `REMARKS` key (JDBC's `getColumns` reads it) and the object's in the schema's metadata;
a statement's result schema names, for each column that is a plain reference to a virtual object's column, that column
(Flight SQL's `CATALOG_NAME` / `SCHEMA_NAME` / `TABLE_NAME`) and its comment (`duckdb:comment`). A column of an alias
relation gets a virtual comment of its own.

## Problem

- **Flight clients see no description.** Flight SQL has no remarks column: a description travels as Arrow metadata
  only, and the door writes none but spec 115's `TYPE_NAME` / precision / scale.
  - DBeaver (JDBC) shows a table's columns from GetTables' `include_schema` - no `REMARKS` there.
  - A pyarrow / ADBC client or an agent reads a result's schema - no comment, no table.
- **DuckDB does not carry them.** v2.0.0 keeps comments in the catalog only. A bound result has names and types, its
  Arrow conversion writes extension types only. Upstream's proposal (duckdb discussion #25917, `duckdb:comment` field
  metadata) is not in the release - and, were it, it would carry the physical sources' comments of the rewritten
  statement, which spec 035 keeps from a principal.
- **An alias relation's column has no virtual comment.** `CREATE VIRTUAL TABLE c.orders AS phys.main.orders` stores no
  column list, so `COMMENT ON VIRTUAL TABLE c.orders COLUMN amount` is refused; its listings show the physical column
  comments.

## Design

### GetTables `include_schema`

- The COLUMNS listing the door runs (`acl_catalog_rpc.cpp`) adds `COLUMN_COMMENT`; `SchemasFor` gives each field
  `ARROW:FLIGHT:SQL:REMARKS` when the column has one (the field metadata `WithTypeNames` builds).
- The TABLES listing adds `TABLE_COMMENT`; the serialized schema's own metadata carries it as `duckdb:comment`
  (Flight SQL has no table-level key; the name is upstream's proposal) - spec 136's unread mark rides with it.
- What the listings show is what goes: the principal's own `information_schema.columns` / `tables` (spec 035's
  visibility, spec 119's narrowing).

### A statement's result schema

- **The origin of a result column.** The rewriter knows the statement as the client wrote it. For the top-level SELECT
  it notes, per result column, the virtual column it is - only when the item is:
  - a column reference resolved to one virtual relation of the FROM (qualified by the relation or its alias, or
    unqualified when the FROM has one relation), renamed or not;
  - or a star (`*`, `t.*`) over one virtual relation - its columns as the principal's listing orders them.
  Anything else - an expression, an aggregate, a subquery, a CTE's column, a set operation's - has no origin. A masked
  column is still the column (the client wrote the column; the mask is the role's view of it).
- The note rides the decision's profile note (spec 074: per statement, by its text's hash); the door takes it with the
  note after `Prepare` and keeps it on the reservation, so GetFlightInfo's schema and DoGet's are the same.
- **What a field carries** (`SchemaFor`, beside `WithTypeNames`): for a column with an origin,
  `ARROW:FLIGHT:SQL:CATALOG_NAME` / `SCHEMA_NAME` / `TABLE_NAME` - the virtual names - and `duckdb:comment` when the
  column has a comment. Never `REMARKS` on a result: arrow-java makes it the column's label (spec 115).
- **The schema's metadata**: when every column comes from one relation, that object's comment as `duckdb:comment`.
- The comments are the principal's own listing's, read once per object and principal and kept until the policy's
  version moves (the store's caches' rule).

### A virtual comment for an alias relation's column

- `COMMENT ON VIRTUAL TABLE c.t COLUMN x IS '…'` (and `acl_comment`) works for any relation: a relation with a stored
  column list keeps it there as today (`object_columns.comment`); an alias relation stores it in a new table
  `column_comments (vcat, vname, column_name, comment)` (schema step v23), its column checked against the source at the
  write. `IS NULL` removes it.
- The listings show the virtual comment, else the physical one - nothing shown today is taken away.
- `acl_check_catalog` reports `comment_column_missing` when a commented column left the source.

## Enforcement & security

- No new visibility: every comment and name comes from the principal's own listings, which already hide what spec 035
  hides (a hidden column has no field; a physical table comment never shows).
- Names in a result's metadata are virtual, never the physical ones the rewrite resolved to.
- The note holds names only, per decided statement, and dies with it.

## Tests

- **sqllogictest**: an alias relation's column comment written, listed (virtual over physical), removed; refused for a
  column the source lacks; the check's finding.
- **C++** (`test/cpp`): the origins the rewriter notes - plain, renamed, qualified by an alias, a star, a join with
  qualified references; none for an expression, an aggregate, a subquery, a CTE, a union, an unqualified reference in
  a join.
- **Flight e2e** (`test/e2e/flight`, pyarrow):
  - GetTables' schema: `REMARKS` per column, `duckdb:comment` for the table;
  - a SELECT's schema at GetFlightInfo and at DoGet: `TABLE_NAME` and `duckdb:comment` per column, the object's comment
    when one relation; none for an expression; a hidden column absent; the physical names nowhere.

## Alternatives considered

- **`REMARKS` on result fields**: arrow-java renames the column to it (spec 115 refused it).
- **Waiting for #25917**: unmerged, and it would carry physical comments through the rewrite.
- **Origins from the plan** (duckdb's `FindBaseTableColumn`, the lineage walker): physical columns of the rewritten
  statement, to be mapped back; the rewriter already holds the virtual names.

## Follow-ups

- **quack** (the owner: later): the server already answers comments in `duckdb_tables` / `duckdb_views` /
  `duckdb_columns`; a quack client reads none at ATTACH, and its protocol has no per-column metadata - an upstream
  duckdb-quack change (and hugr-node's `hugr` type, its copy).
- ADBC Go's GetObjects leaves column remarks NULL (an upstream ADBC gap).
