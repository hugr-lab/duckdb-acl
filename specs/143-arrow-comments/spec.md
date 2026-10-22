# Spec 143: comments and tags reach Flight clients in the Arrow schema

- **Status**: implemented
- **Date**: 2026-10-22
- **Author**: hugr lab (the owner, 2026-10-19 and 2026-10-22: "описания колонок и объекта должны быть и должны быть видны
  в Arrow"; result schemas with their names; a virtual column comment, else the physical one; quack later; and tags -
  the physical catalog's until the virtual catalog has its own)

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

- The COLUMNS listing the door runs (`acl_catalog_rpc.cpp`) reads `duckdb_columns()` - the same rows as
  `information_schema.columns`, with `comment` and `tags`; `SchemasFor` gives each field
  `ARROW:FLIGHT:SQL:REMARKS` when the column has one (beside `WithTypeNames`' metadata).
- `include_schema`'s tables listing (`DESCRIBED_TABLES`) adds `TABLE_COMMENT` after the protocol's columns (not
  sent: `BatchFrom`'s `trailing`); the serialized schema's own metadata carries it as `duckdb:comment` (Flight SQL
  has no table-level key; the name is upstream's proposal) - spec 136's unread mark rides with it. The objects'
  tags are read for the listed objects alone (`PolicyStore::ObjectTags`: the session principal's own tables
  listing with its hidden tags kept, narrowed to them) - not through `duckdb_tables()`, whose shape costs a planner
  pass per call (spec 121's measurement; the review's: 2.85 s a call against 0.83 s before the branch, now 1.05 s).
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
- The origins are noted for a Flight session's batch only (the override's door; `AuditTrail::origins`), off a copy
  of the statement taken before the rewrite replaces the relations and read once the rewrite has decided it (a
  policy source that fails there still refuses), and ride the decision's profile note (spec 074: per statement, by its text's
  hash); the door takes it with the note after `Prepare` (on the reservation). A star is a span: its length is the
  result's to say, so a second star, `COLUMNS(…)` or a star with modifiers leaves the statement without origins.
- The door says nothing rather than the wrong thing (the review's misattributions): a list that does not fit the
  fields is dropped - a star of no column (a placeholder schema), an item whose name the text gives (its alias, a
  reference's last part) landing on a field of another name (an item beside it made several columns), a star over
  an object whose span is not that object's columns; and a column is labelled only when the object's description
  lists it (not a struct column's field `t.x` duckdb read off another relation, a lateral alias, `current_schema`).
- **What a field carries** (`SchemaFor`, beside `WithTypeNames`): for a column with an origin,
  `ARROW:FLIGHT:SQL:CATALOG_NAME` / `SCHEMA_NAME` / `TABLE_NAME` - the virtual names - and `duckdb:comment` when the
  column has a comment. Never `REMARKS` on a result: arrow-java makes it the column's label (spec 115).
- **The schema's metadata**: when every column comes from one relation, that object's comment as `duckdb:comment`.
- The comments are the principal's own listing's (`PolicyStore::DescribeObject`: the tables and columns listings
  with their hidden tags kept, narrowed to the object, on the store's connection), read once per role set and object
  and kept until the policy's version moves or ten minutes pass (a source's own comment or tags change without it) -
  an object no listing shows kept as none; the door reads them at Prepare onto the reservation, so GetFlightInfo's
  schema, CreatePreparedStatement's and DoGet's say the same. Measured through the door: the first statement over an
  object pays ~0.3 s once (the columns listing's own cost), the next nothing.

### A virtual comment for an alias relation's column

- `COMMENT ON VIRTUAL TABLE c.t COLUMN x IS '…'` (and `acl_comment`) works for any relation: a relation with a stored
  column list keeps it there as today (`object_columns.comment`) and takes none for a source column its list does not
  read; one with no list over a source - an alias, or one that only filters its rows (RLS) - stores it in a new table
  `column_comments (vcat, vname, column_name, comment)` (schema step v23), its column checked against the source at the
  write. `IS ''` removes it, as for any comment - a kept one first, whatever the relation is now.
- The listings show the virtual comment, else the physical one - nothing shown today is taken away.
- `acl_check_catalog` reports `comment_column_missing` when a kept comment is shown by no listing: its column left the
  source, or the relation came to declare its columns (each then has its own comment) - with the `IS ''` repair.

### Tags

DuckDB v2.0.0 keeps tags (`MAP(VARCHAR, VARCHAR)`) on every catalog entry - databases, schemas, tables, views, columns,
functions - and lists them (`duckdb_*().tags`); no SQL statement sets them in the release, a source's extension does
(DuckLake's tags, say). The virtual catalog has none of its own yet (a later spec), so a principal's listings answer an
empty map today. Now they answer the physical catalog's where a virtual object has one physical counterpart:

- an alias relation: its table's tags, its columns' tags;
- a declared list or a projection over one physical table: each column's tags by the source column it reads (a
  computed column has none); the object's tags are its table's;
- a masked column keeps its column's tags (the column is the same; the role sees its values masked) - and its
  comment: a grant that names a column (spec 026's projection) used to drop the column's comment from the listing,
  found by the e2e;
- a live schema alias: its schema's (`duckdb_schemas`; the schema looked up by `acl_physical_schemas(keys)`, its
  tables never scanned), tables' and columns' tags;
- a virtual view, a table function, a computed column, a catalog: none - and nothing is derived from the query that
  defines a view or a function (the owner, 2026-10-22): such an object and its columns carry only the comments given
  to them in the virtual catalog (`COMMENT ON VIRTUAL VIEW|TABLE FUNCTION … [COLUMN …]`).

They go wherever the comments go:

- the listings' `tags` (`duckdb_tables`, `duckdb_views`, `duckdb_columns`, `duckdb_schemas`; the physical readers -
  `acl_physical_tables` / `_columns`, spec 119 - carry them, and the information_schema surfaces drop the column:
  their shape is duckdb's);
- a declared column reads its source column's tags by the rule spec 039's broken mark reads it by: no expression, or
  a bare or quoted identifier that is no special value (`NULL`, `current_date`, ...);
- Arrow, one key per tag: a field's `duckdb:tag:<key>` = value (GetTables' schema, a result column with an origin), a
  table's in its schema's metadata (GetTables' table, a result from one relation). A schema's tags reach the listings
  only: Flight SQL's GetDbSchemas has no metadata to carry them.

## Enforcement & security

- No new visibility: every comment and name comes from the principal's own listings, which already hide what spec 035
  hides (a hidden column has no field; a virtual object never shows its source's table comment - a live alias
  schema's tables are the source's own, comment included).
- Found by the review (a negative test in `acl_column_comments.test`): a grant's projection (spec 026) listed a column
  an object grant names but the catalog grant's list hides - the read has no such column - and this spec would have
  carried its comment and tags; the leg now lists only a name every level of a role's grants keeps (spec 035).
- Tags are the physical catalog's, as the owner decided for now: they may name what the source's operator wrote. A
  hidden column's tags never show (no row); the policy's own tags will replace them when the virtual catalog has them.
- Names in a result's metadata are virtual, never the physical ones the rewrite resolved to.
- The note holds names only, per decided statement, and dies with it.

## Tests

- **sqllogictest**: an alias relation's column comment written, listed (virtual over physical), removed; refused for a
  column the source lacks; the check's finding (`acl_column_comments.test`). A DuckLake table's tags on an alias
  relation, a view's empty (`acl_physical_tags_ducklake.test`; DuckLake applies a column's tag only as its comment).
- **C++** `test_acl_physical_tags.cpp`: no SQL statement of the release sets a tag, so the tagged schema and table are
  made through the catalog API - an alias relation's table and columns, a declared list's columns by the source column
  (a computed one none), a live schema alias's schema, tables and columns, a masked column's kept, a hidden one's
  absent, a view's none, information_schema's shape unchanged.
- The origins the rewriter notes are checked where they are written, the Flight e2e below: the extension's internals
  are not exported from libduckdb, and a C++ test cannot open a Flight-door session to reach them.
- `test_acl_catalog_rpc.cpp`: the described tables and tags listings and the columns listing's comment, under a role.
- **Flight e2e** (`test/e2e/flight/run.sh`, pyarrow; `client.py`'s `ACL_SHOW_DESCRIBED`):
  - GetTables' schema: `REMARKS` per column (a virtual comment on an alias relation's column, a source's where there
    is none), `duckdb:comment` for the table, a hidden column absent;
  - a SELECT's schema at DoGet, equal to GetFlightInfo's: catalog / schema / table and `duckdb:comment` per column
    (plain, renamed, a star, a join by aliases), the object's comment for one object; none for an expression, an
    aggregate, a CTE's column, a union; the physical names nowhere; a prepared statement's announced schema;
  - tags as `duckdb:tag:<key>` on a GetTables schema and a result's, from a DuckLake table (where the build has it).

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
- Found while testing and reviewing (not this spec's, each its own spec):
  - a live schema alias's columns are listed whole under a catalog grant whose `COLUMNS` narrows what the read
    returns - the listing shows a column name (and now its tags) the read hides (spec 035's rule);
  - a catalog grant's struct path (`COLUMNS (id, addr.city)`) lists `addr` with its hidden fields in its type (an
    object grant's lists `STRUCT(city …)`, spec 102);
  - `SELECT * LIKE '%t%' FROM t` under a principal names its columns `(* ~~ '%t%')` (spec 072's `KeepItemNames`).
