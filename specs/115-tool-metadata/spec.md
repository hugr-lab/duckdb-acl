# Spec 115: metadata for tools

- **Status**: implemented (accepted by the owner 2026-10-09)
- **Date**: 2026-10-09
- **Author**: Claude (design/079 with the owner)
- **Follows**: spec 046 (Flight catalog RPCs), spec 048 (column metadata), spec 098 (a principal's
  functions), spec 099 (types), spec 114 (the session's catalog). Phase 0 of design/079 (DBeaver as
  the management console); its client half is acl-clients spec 006.

## Summary

What a database tool (DBeaver, DataGrip, an ADBC or JDBC client) learns about the node through the
Flight door, made complete and correct: how to quote and qualify names, the real type of every
column (a `STRUCT(city VARCHAR, …)`, not `JAVA_OBJECT`), the type list, and the principal's
functions - scalar and table, in every catalog it holds, with parameters and a table function's
result columns - and schemas with their parent, so a tree can be built. Nothing here grants or
reveals more than the principal's own listings already do.

## Problem

Measured 2026-10-09 with the Arrow Flight SQL JDBC driver 19.0.0 against a seeded node:

- `getIdentifierQuoteString` is `''` (names are never quoted - a keyword or a mixed-case name
  breaks), `isCatalogAtStart` is false, the catalog / schema terms are empty, transactions read as
  unsupported. The door's `GetSqlInfo` registry (`src/flight/acl_flight_door.cpp` ~1081) carries
  only name / version / read_only / sql / substrait / transaction / cancel / bulk ingestion.
- `GetXdbcTypeInfo` is not implemented (NotImplemented): `getTypeInfo` is empty.
- A column's `TYPE_NAME` is generic: STRUCT / MAP → `JAVA_OBJECT`, LIST → `ARRAY`. Arrow's
  `getColumns` takes the Flight SQL field metadata `ARROW:FLIGHT:SQL:TYPE_NAME` when the server sets
  it; we do not (`SchemasFor` in `src/flight/acl_flight_catalog.cpp`, `SchemaFor` in the door).
- Functions are nowhere: Flight SQL has no RPC for them, and `duckdb_functions()` under a principal
  (spec 098) lists only the flat names of the one MAIN catalog - a function of another catalog or of
  a nested schema is missing, and a table function's result columns are not exposed at all (stored
  in `object_columns`; spec 098's named follow-up `acl_function_columns`).
- A nested schema is one dotted `schema_name` (`raw.eu`) and `duckdb_schemas.parent_schema` is NULL
  in the principal's listing (`src/acl_metadata_listing.cpp` ~236); a schema holding only functions
  is not listed (~135).

## Design

### 1. SqlInfo

Register, beside the existing entries, the values a tool reads to build names and pick features:
`SQL_IDENTIFIER_QUOTE_CHAR` = `"`, `SQL_IDENTIFIER_CASE` and `SQL_QUOTED_IDENTIFIER_CASE` =
case-insensitive (duckdb folds both), `SQL_CATALOG_TERM` = `catalog`, `SQL_SCHEMA_TERM` =
`schema`, `SQL_PROCEDURE_TERM` = `function`, `SQL_CATALOG_AT_START` = true,
`SQL_SEARCH_STRING_ESCAPE` = `\` (and the catalog RPCs' `LIKE` filters apply it), `SQL_KEYWORDS`
(duckdb's reserved words plus ours:
`ACL`, `NATIVE`, `VIRTUAL`, `ISSUER`, `CLIENT`, `MAP`, …), and the transaction support entry Arrow's
`supportsTransactions` reads (verify which: the door already has transactions, spec 055). Static
values of the node - no principal, no policy in them.

### 2. Type names in the field metadata

Every Arrow field the door describes - GetTables `include_schema`, a statement's dataset schema, a
prepared statement's parameter schema - carries `ARROW:FLIGHT:SQL:TYPE_NAME` = duckdb's type text of
what the principal reads (spec 099's exposed type; spec 102's listed type for a narrowed struct),
plus `PRECISION` / `SCALE` for DECIMAL (nullability stays the Arrow field's own flag, spec 048). Never `REMARKS` on a result
schema: Arrow 19 copies it into the column label (and renames the column).

### 3. GetXdbcTypeInfo

Answered from the system catalog's types (`duckdb_types()` filtered to `system`, spec 099's rule):
one row per type a principal may name, with the xdbc data type, the literal prefix / suffix, nullable,
case sensitivity and searchable. Static per build.

### 4. The principal's functions, in every catalog

`duckdb_functions()` under a principal (spec 098's surface, `PrincipalFunctionsSql`) lists the
virtual functions of **every catalog the principal holds**, each with its catalog and its schema
path (a nested schema as its dotted path, like the tables listings), confirmed as today with
`Resolve*Function` + `select`. For a table function `return_type` is `TABLE(<col> <type>, …)` of its
declared result columns, so one listing answers a simple client.
New surface **`acl_function_columns([catalog[, schema[, function]]])`** under a principal: one row per
result column of a table function it can call (`database_name, schema_name, function_name, position,
column_name, data_type, is_nullable, comment`) and per parameter (`column_kind` = `param` / `column` /
`return`) - what
JDBC `getFunctionColumns` / `getProcedureColumns` need. Rewritten like `acl_keys()` (substituted
before the function gate), from `object_columns` + `functions.params`; nothing probed.

### 5. Schemas with their parent

The principal's `duckdb_schemas` answers `parent_schema` (the dotted path's prefix, NULL at the
root) and lists a schema that holds only functions. `information_schema.schemata` stays the flat
standard shape.

## Enforcement & security

- 1 and 3 are static facts of the build: no principal state, no policy.
- 2 describes only columns the principal already receives (the schema of its own statement, or its
  own GetTables answer) - the type text is the one its listings already show (`information_schema.
  columns.data_type`, spec 099's exposed type). A narrowed struct shows the narrowed type.
- 4 and 5 widen spec 098's surface from the MAIN catalog to every held catalog: each function is
  confirmed with the same resolution and `select` judgment a call gets, so a function the principal
  cannot call is not listed. `acl_function_columns` lists only those. The never set and engine
  functions follow spec 098 unchanged.

## Testing

- `test/sql/acl_tool_metadata.test`: the principal's `duckdb_functions()` across two catalogs and a
  nested schema (a function the role cannot call absent); a table function's `return_type`;
  `acl_function_columns()` (params and columns, a refused function absent); `duckdb_schemas`
  `parent_schema` and a functions-only schema.
- Flight e2e (pyarrow, and ADBC reading the field metadata): `GetSqlInfo` values; `GetXdbcTypeInfo` rows; the `TYPE_NAME` metadata
  of a STRUCT / LIST / MAP / DECIMAL column in GetTables `include_schema` and in a statement's
  schema; a narrowed struct's listed type.
- acl-clients spec 006's live JDBC dump (`getIdentifierQuoteString`, `isCatalogAtStart`,
  `getColumns.TYPE_NAME`, `getTypeInfo`, `getFunctions`) against a node with this spec.

## Alternatives considered

- **`information_schema.routines` / `parameters`**: the standard shape, but duckdb has neither view;
  inventing them only under a principal would make the native and the principal's catalogs differ.
  `duckdb_functions()` already is the surface, and the new listing is acl-named like `acl_keys()`.
- **Functions as GetTables rows** (`TABLE_TYPE = 'TABLE FUNCTION'`): spec 046 decided against it - a
  function is no table, and tools would try to `SELECT *` from it.
- **Fixing it only in the driver**: the driver can (and spec 006 does) fill the gaps for JDBC, but
  every other Flight client (ADBC, pyarrow, Go) would still read wrong quoting and generic types.

## Follow-ups

- The management console itself (design/079 phases 1–4): the `platform` catalog (spec 116), node and
  cluster (spec 117), the DBeaver plugin (acl-clients spec 007).

## As built

- **A virtual function of any held catalog is now callable** - found while building the listing: the
  rewriter passed only a call's bare name to the resolver, dropping its catalog and schema, so
  `other.f(…)`, `FROM c.nested.f()` were refused ("in no function category") although the resolver
  reads `c.f` / `c.a.b.f`. `AclRewriter::ResolveVirtualFunction` resolves the name as written (and,
  under a session's `USE`, spec 114, the short name in its catalog first - spec 114's named
  follow-up); `CatalogBackend::ResolveFunction` reads `<vcat>.main.<f>` as the root, as spec 112 does
  for a relation. A bare call still reaches only the MAIN catalog (and an engine function).
- `CatalogBackend::VisibleFunctions` lists every held catalog's functions with a `bare` flag (only
  those shadow an engine function in the engine half of the listing) and the declared result columns;
  `CallableFunctions` (acl_principal_functions.cpp) confirms each with the qualified resolution and
  `select`. `acl_function_columns` rows: `column_kind` = `param` / `column` / `return`.
- `duckdb_schemas` under a principal: every parent of a nested path is listed (`raw`, `raw.eu`), with
  `parent_schema` / `parent_schema_oid`; a catalog or schema that holds only functions is listed.
- SqlInfo: identifier quote, identifier / quoted-identifier case (insensitive, as duckdb folds),
  catalog / schema / procedure terms, catalog at start, search escape, `SQL_TRANSACTIONS_SUPPORTED`
  (what Arrow JDBC's `supportsTransactions` reads; `FLIGHT_SQL_SERVER_TRANSACTION` stays),
  `SQL_KEYWORDS` (duckdb's reserved words + the management grammar's).
- `WithTypeNames` (acl_flight_catalog.cpp) merges the column metadata into every field the door
  describes; GetTables `include_schema` uses the listing's own type text.
- GetXdbcTypeInfo: a static table of the system types with JDBC codes (`XdbcTypeInfoBatch`).
- Tests: `test/sql/acl_tool_metadata.test`, `test/sql/acl_principal_functions.test` (spec 098's
  expectations moved: another catalog's and a nested function are listed and callable qualified),
  `test/cpp/test_acl_session_use.cpp` (a function's short name under `USE`), Flight `run.sh`
  (`@sqlinfo`, `@xdbc`, `TYPE_NAME` on results and in `include_schema`).
- **Review fixes** (2026-10-09):
  - `<vcat>.main.<f>` is a fallback, never a second match: `PolicyStore::ResolveFunctionNamed` resolves
    the name as written and only then the root - one query matching both `f` and a nested `main.f`
    merged two functions' caps (a `CAPS '{}'` on one was opened by the other). The segment must be
    `main` as written: a stored name is matched exactly, so `c.MAIN.f` must not miss `main.f` and land on
    `f`. `PolicyStore::ResolveTable`'s spec-112 fallback takes the same rule.
  - A table function's listed result is what the call returns: the grant's projection is bound
    (`NarrowedColumns`, `DESCRIBE` on the node over an empty relation of the declared columns) - a hidden
    column is not listed, a mask's type is the binder's; a projection that does not bind withholds the
    list.
  - The catalog RPCs' pattern filters carry `ESCAPE '\'` - the escape SqlInfo announces (a JDBC tool
    escapes `_` in a name it looks up). XdbcTypeInfo: a type without params has an empty list.
- **What changed for every listing**: the principal's schema set (`information_schema.schemata`,
  `duckdb_schemas`, `duckdb_databases`, SHOW SCHEMAS/DATABASES, Flight GetCatalogs/GetDbSchemas) now
  includes each parent of a nested schema and a schema or catalog that holds only functions - the
  nodes a tree needs. A functions-only schema is listed by the same not-`'{}'` rule as a relation's
  (`select` is not required to list a name, as for an insert-only relation).
- **Known edges**: method-call syntax `x.f()` where `x` is a column and also a held catalog with a
  virtual `f` now takes the virtual function (it fails closed when the arguments do not fit); under a
  session's `USE` the session catalog's flat functions also shadow engine functions, which the
  listing's `bare` flag (MAIN only) does not mark.
