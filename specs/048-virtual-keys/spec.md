# Spec 048: the declared shape of an object - keys and nullability

- **Status**: implemented
- **Date**: 2026-08-27
- **Author**: hugr-lab

## Summary

A virtual object can declare its own shape beyond columns and types: **a primary key** and
**per-column nullability** - both declarations in the spec-022 sense (granting nothing, enforcing
nothing, visible only as far as the role sees), both riding the object's own declaration, both
consumed by the same two kinds of reader: the metadata surfaces and the Flight door's protocol
answers.

`GetPrimaryKeys` answers empty (spec 046, deliberately: a physical key is not a fact about a virtual
object), and `duckdb_tables().has_primary_key` answers NULL (spec 035, same rule). Both stay honest
by refusing to describe the physical world - but a virtual object can carry a key *of its own*, the
way spec 022 gave it references: **declared, granting nothing, enforcing nothing**. The declaration
rides the object itself - `PRIMARY KEY (col, ...)` on `CREATE VIRTUAL TABLE`, on `CREATE VIRTUAL
VIEW`, and beside `RETURNS` on a table function - because a key is a property of one object, not a
relationship between two, so it earns a clause, not a catalog entity. The spec also closes the last
cheap write-path gap: `DoPutCommandStatementUpdate`, the text-DML DoPut that JDBC's `executeUpdate`
speaks.

## Problem

A JDBC/ODBC tool asks `GetPrimaryKeys` for the one thing it wants before offering editing, joins in
a diagram, or a merge key - and we answer "none", for every object, forever. The information often
*exists*: the admin who declared `c.orders` knows its key. There is nowhere to say it. Meanwhile
`has_primary_key` NULL reads as "unknown" to a person but as "no" to most drivers.

And on the write side: adbc-go happens to route text DML through the query path, but JDBC's
`executeUpdate` is `DoPut(CommandStatementUpdate)` - unimplemented, so a JDBC client's plain
`INSERT` fails with NotImplemented while the same text works from ADBC. One skeleton (the prepared
update without parameters) closes it.

## Design

### Syntax: a clause, not an entity

```
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders
    COLUMNS (id, tenant, amount) PRIMARY KEY (id) RLS '...' COMMENT '...';
ACL ADMIN CREATE VIRTUAL VIEW c.stats AS 'SELECT ...' PRIMARY KEY (day);
ACL ADMIN ADD TABLE FUNCTION c.report(...) RETURNS (...) PRIMARY KEY (id) MACRO '...';
ACL ADMIN ALTER VIRTUAL TABLE c.orders SET PRIMARY KEY (id, tenant);
ACL ADMIN ALTER VIRTUAL TABLE c.orders DROP PRIMARY KEY;
```

The clause joins the existing Accept-loop (`COLUMNS` / `RLS` / `COMMENT`), so order stays free. The
function forms take it after `RETURNS` - a key describes the *result*, and a function without a
declared or probed result schema cannot carry one. The `acl_add_*` functions gain a `pk` argument;
a written key names only columns the object's declaration has, checked where it is written -
validation, not enforcement.

**Enforcement is exactly none, and that is the design.** Like a reference (spec 022), a declared key
is a hint a client or an agent reads: it does not create an index, does not reject duplicates, does
not imply NOT NULL. duckdb could not enforce it against a remote source anyway; pretending otherwise
would be the lie spec 035 exists to prevent. `update_rule`-style honesty, applied to keys.

### Storage: one new table, and the first migration step

`<keys>("vcat" KEY, "vname" KEY, "kind" KEY, "pos" INTEGER, "column" VARCHAR)` in the managed schema
- `kind` mirroring `object_columns` (`relation` / `table`), so a table, a view and a table function
store keys the same way. The table joins `policy_schema.sql`, `make schema` regenerates,
`ACL_SCHEMA_VERSION` steps 10 -> 11. `CREATE TABLE IF NOT EXISTS` covers the new table but cannot
add `nullable` to columns tables that already exist, so this version is the first to need a real
step: `schema/migrations/v11.sql` (the spec-034 contract). `acl_use_db(..., true)` refuses an older
stamp by version and points at the migrations instead of re-stamping - replaying the schema over a
v10 catalog and claiming v11 left broken tables behind the one honest failure.

### The surface: `acl_keys()`, the spec-022 pattern verbatim

A principal reads keys through `acl_keys([object])` - substituted in the rewriter before the
function gate, exactly as `acl_references()` is, and visible under the same rule: **a key is listed
only when its object and every column it names are visible to the role.** A grant that hides `id`
hides the key that names it - a listed key a role cannot select is a description of something it
cannot see. The same rule reaches a table function: a grant's columns list narrows its result
exactly as it narrows a relation (spec 011), so a function's key hides with any narrowed-away
column.

Two consumers, one source:

- **`GetPrimaryKeys`** (the Flight door) composes over `acl_keys()` filtered to the named table
  and to `kind = 'relation'` - a table function sharing the table's name declares its own key, not
  the table's. The spec-046 rule unchanged: the door holds a mapping, not a policy. `key_sequence` from `pos`
  (1-based), `key_name` = `'<vname>_pk'`.
- **`has_primary_key`** in `duckdb_tables()` flips from NULL to an honest EXISTS over the same rows.
  The spec-035 table gains a row: it is no longer a physical fact being refused but a virtual
  declaration being reported. The metadata-shapes leak assertion moves `has_primary_key` from the
  "must be NULL" set to a consistency check against `acl_keys()`.

### What the second review round settled

- **A key is a declaration the redefinitions respect.** `CREATE OR REPLACE` and every `ALTER` that
  does not state a key *carry* the stored one (exactly as the comment is carried), together with the
  declared nullability marks - wherever they live (`relation_columns` or `object_columns`). A
  carried key is not re-litigated: when the new shape no longer has its column, it **lapses**
  (silently, only the delete is written) instead of blocking a redeclaration the admin never tied to
  it. Removing a key on purpose is `ALTER ... DROP PRIMARY KEY` - a view alters its key too, and a
  scalar cannot (`ALTER VIRTUAL SCALAR ... SET PRIMARY KEY` does not parse, as with CREATE).
- **A masked column cannot be keyed by implication.** A projection entry that is an expression may
  answer NULL whatever the physical rows hold, so `PRIMARY KEY` over it is refused unless the admin
  also writes `NOT NULL` after the mask - an explicit promise is theirs to make, and the surface
  then reports the mark, not the implication. A bare rename is not an expression, and a mask ending
  in its own `IS NOT NULL` is kept whole - only the trailing `NOT NULL` mark is stripped.
- **A bare alias' key is validated after all**: the source is probed (`SELECT * ... WHERE false`)
  for the check alone, storing nothing; a source that does not bind leaves the key
  uncheckable-accepted, the predicate rule verbatim.
- **Known limitation:** a *grant-level* mask that keeps the column's type is not stored (spec 026
  stores only type-changing masks and computed columns), so a role reading a declared-NOT-NULL
  column through such a mask still sees `is_nullable = 'NO'` and the Arrow non-null promise. The fix
  is storing every masked name, which belongs to spec 026's table, not here.
- **`DESCRIBE` stays generic**: spec 025 describes the rewritten relation through duckdb's own
  subquery describe, whose `null`/`key` columns are always `YES`/`NULL`. The declared shape lives in
  `information_schema.columns`, `duckdb_columns()`, `acl_keys()` and the Arrow schema; making
  DESCRIBE agree would mean synthesizing its answer and is not worth diverging from spec 025.

### `DoPutCommandStatementUpdate`: the prepared update, minus parameters

The reservation store is not involved: the command carries the SQL text, the caller's session
composes it, one `Prepare` + `Execute` on a call-local connection, the count returns. The
transaction wrapper is unnecessary for a single statement; the BIGINT-count guard from the
executemany fix applies. Multi-statement strings keep their refusal (design/013 §10: the ecosystem's
reference silently drops tails; our verbatim error is already the better behavior).

### Nullability: the same declaration, per column

**Syntax** - a suffix where a column is declared:

```
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders
    COLUMNS (id NOT NULL, tenant, ssn = NULL) PRIMARY KEY (id);
ACL ADMIN ADD TABLE FUNCTION c.report(...) RETURNS (id INTEGER NOT NULL, name VARCHAR) ...;
```

Unambiguous against the mask form (`ssn = NULL` masks; `id NOT NULL` declares). In `RETURNS` the
suffix is stripped into a flag *before* the type parses - `ParseDeclaration` splits on the first
space, so `INTEGER NOT NULL` must never reach `TransformStringToLogicalType` (measured: it refuses).

**Storage**: a `"nullable" BOOLEAN` column on both `relation_columns` (the alias-form projection
list) and `object_columns` (stored schemas) - NULL meaning *undeclared*. Same pre-release rule as
the keys table: straight into `policy_schema.sql`, one version step (10 -> 11) covers both.

**Reporting, one precedence everywhere**: declared wins -> physical flows (an alias-form column
without a declaration keeps the live source's `is_nullable`, as today) -> default nullable. A
**primary-key column reports NOT NULL implicitly** - relational semantics every consumer assumes -
and an explicit nullable declaration on a PK column is refused at write, naming the conflict.

**The Arrow promise carries it**: duckdb's `ToArrowSchema` hardcodes `ARROW_FLAG_NULLABLE` on every
field (measured - the signature takes no nullability at all), so `get_table_schema` and
`include_schema` post-process the imported schema, clearing the flag on declared-NOT-NULL columns.
What a client is promised again matches what the declaration says.

**Declared, not enforced - with one honest follow-up.** Unlike a key, NOT NULL *could* be enforced
cheaply on ACL writes: spec 024's injection machinery (`CASE ... ELSE error() END`) already judges
every written row, and a NULL-check is the same shape. That is deliberately left out of this spec -
enforcement changes what a declaration *is*, and deserves its own decision - but the door is left
open and named, rather than discovered.

## Enforcement & security

- **A key and a nullability mark grant nothing and enforce nothing** - it cannot widen access, only describe it. The
  visibility rule keeps it from describing what a role cannot see.
- **Validation at write**: a key naming a column the object's declaration lacks is refused where the
  admin writes it, with the column named. (For an alias-form table the declaration is the physical
  schema at declaration time; `acl_refresh_schema`'s existing limits apply - a source that drops a
  key column later leaves a dangling key name, same family as the projection-refresh backlog item.)
- **`DoPutCommandStatementUpdate` is the statement path's twin**: same session, same composition,
  same rewriter, same verbatim refusals - a JDBC `executeUpdate` of a cross-tenant row dies on
  spec 024's message exactly as the query path does.

## Testing

- **sqllogictest, nullability**: `NOT NULL` in COLUMNS and in RETURNS lands in
  `information_schema.columns.is_nullable` and `duckdb_columns().is_nullable`; an alias column
  without a declaration keeps the physical answer; a PK column reports NOT NULL with no explicit
  mark; `NULL`-declared PK column refused at write; the promised Arrow schema (raw client
  `@tables_schema`) shows the field non-nullable.
- **sqllogictest, keys**: declare keys on a table, a view, a function; `acl_keys()` lists them in
  position order; a role whose grant hides a key column does not see the key; `has_primary_key`
  answers true/false consistently with `acl_keys()`; ALTER SET/DROP round-trips; a key naming a
  missing column is refused at write with the column named.
- **C++** (`test_acl_catalog_rpc.cpp`): the GetPrimaryKeys composition over `acl_keys()` - filters,
  ordering, catalog qualification (the review's lesson from the FK RPCs applied on day one).
- **e2e through the real driver**: `adbc_get_objects(depth="tables")`... plus raw-client
  `@pk:orders` returns the declared key; a JDBC-path text INSERT via `executeUpdate` lands and a
  cross-tenant one is refused verbatim (extends `adbc.sh` - the driver's `cur.execute` with
  `IngestTargetTable` unset exercises DoPutCommandStatementUpdate through `adbc_statement`... the
  update path is reachable via `cursor.executeupdate` in the dbapi; measured while implementing).
- Views and references through the driver (the 048 promise from design/013 §6): the e2e bootstrap
  gains a view; `get_objects` shows it typed VIEW; `@imported`/`@exported` stay green.

## Alternatives considered

- **`CREATE VIRTUAL KEY` as its own entity** - rejected with the user: a key is a property of one
  object; a separate entity buys nothing but lifecycle bookkeeping (spec 022's references earn
  theirs by connecting *two* ends).
- **Storing the key in `relations.pk` / `functions.pk` columns** - an ALTER on two existing tables
  against a new table nothing has to migrate; and per-column rows keep position first-class.
- **Enforcing uniqueness** - impossible against remote sources without reading them, and a half
  enforcement is worse than a declaration.

## Follow-ups

- Importing physical PKs as declared defaults at `CREATE VIRTUAL TABLE` time (an admin convenience;
  spec 022 left the same door open for FKs).
- `duckdb_constraints()` as a principal surface, if a tool ever reads it.
- Spec 049: ingest - `DoPutCommandStatementIngest` by spec 042's staging pattern; flips
  `FLIGHT_SQL_SERVER_BULK_INGESTION` to true.
