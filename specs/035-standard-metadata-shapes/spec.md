# Spec 035: a metadata surface answers in its own shape

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

Spec 010 replaces duckdb's metadata surfaces with a listing of the principal's own catalog, but it
collapses eight written names onto four listings — so under a principal `duckdb_tables()` answers with
`information_schema.tables`'s columns. A human typing `SELECT *` never notices; a client that selects
columns by name breaks, which is every tool that reads a catalog programmatically. Each surface now
answers in **its own standard shape**, column for column and type for type, and the values that would
describe the physical object rather than the virtual one (`sql`, `estimated_size`, the oids) are
answered about the object the principal actually has.

## Problem

`MetadataSurfaceOf` maps the written name to one of four listings:

```text
information_schema.tables → tables      duckdb_tables   → tables
information_schema.columns → columns    duckdb_views    → tables
information_schema.schemata → schemata  duckdb_columns  → columns
                                        duckdb_schemas  → schemata
                                        duckdb_databases → databases
```

and `MetadataListingSql` builds each listing out of `information_schema.*`. So the shape a caller gets
is the shape of the *information_schema* surface, whatever they wrote. Probed on the current build,
against the catalog load query the quack extension runs when a client attaches:

```text
ACL ROLE "analyst" SELECT schema_name, sql, 'table' FROM duckdb_tables()
                   UNION ALL SELECT schema_name, view_name, 'view' FROM duckdb_views();
Binder Error: Referenced column "schema_name" not found in FROM clause!
Candidate bindings: "table_name", "table_schema", "commit_action", "table_catalog", …
```

Three consequences:

1. **A quack client cannot attach at all.** `QuackTableSet::GetLoadQuery()` selects `schema_name` and
   `sql` from `duckdb_tables()`; neither column exists under a principal. The same applies to any
   consumer that names columns — which is what a program does.
2. **`duckdb_views()` does not exist as a distinct answer.** It returns table rows, so a client asking
   for views gets tables, with `view_name` missing.
3. **The columns that do survive can say more than they should.** The listing borrows `i.*` from the
   physical `information_schema` row, so anything we did not think to replace is a physical fact:
   `estimated_size` describes rows an RLS predicate hides, `sql` is the physical `CREATE TABLE` naming
   the physical object, and the oids identify physical catalog entries.

A fourth turned up while implementing: **`information_schema.columns` had a 46th column.** The
synthesized branch of the columns listing aliased its comment as `comment`, while the real surface
calls it `COLUMN_COMMENT`, and `UNION ALL BY NAME` duly added both. So even the surface whose shape
was supposed to be inherited was not the standard one.

None of this is a deliberate limitation. The header comment on `MetadataListing` already claims
"duckdb's own shape"; the code did not do it.

## Design

**The written name decides the shape.** `MetadataSurfaceOf` returns a surface per name rather than per
concept — `duckdb_tables`, `duckdb_views`, `duckdb_columns`, `duckdb_schemas`, `duckdb_databases`,
`tables`, `columns`, `schemata` — and the substitution point in the rewriter is unchanged: it still
asks for a surface and gets a `SELECT` back. `SHOW`'s surfaces (spec 031) are untouched; they already
work this way, and this spec is the same principle applied to the table functions.

**One set of rows, projected per shape.** The two listings that do the real work — the tables listing
and the effective-columns listing — stay as they are, in the `information_schema` shape, built by
joining the physical surface and replacing the identity columns. Each duckdb-shaped surface is then a
projection of one of them.

That is better than joining `duckdb_tables()` physically for the duckdb shapes, which was the obvious
alternative: a projection can only produce the columns it names, so a physical fact cannot arrive by
being forgotten. `duckdb_tables()` and `duckdb_views()` project the tables listing (filtered on
`table_type`, since duckdb answers those two questions separately); `duckdb_columns()` projects the
columns listing, converting `is_nullable` and `is_generated` from the strings `information_schema`
uses to the booleans duckdb uses; `duckdb_schemas()` and `duckdb_databases()` project the schema
listing.

The three-part structure of the underlying listings is unchanged: physical objects join the physical
surface and have their identity columns replaced; virtual objects with no physical row behind them (a
view, a projection, a computed column) are synthesized and folded in with `UNION ALL BY NAME`, so a
column the synthesized branch cannot fill arrives as NULL rather than as a missing column — which is
also why the synthesized branch has to spell a column's name exactly as the real surface does.

**`sql` is synthesized from what the role reads.** `duckdb_tables().sql` becomes a
`CREATE TABLE <virtual name>(<column> <type>, …)` built from the effective column listing — the same
one `duckdb_columns()`/`information_schema.columns` answers with, which already folds in a grant's own
projection (spec 026: a mask that changes a type, a computed column the object never had). That makes
the three answers consistent by construction: what `DESCRIBE` says, what the columns listing says, and
what the DDL says are the same statement. It also has to be *valid*, because a quack client parses and
binds it (`ParseCreateTable` → `BindCreateTableInfo`).

`duckdb_views().sql` and `duckdb_schemas().sql` are NULL: the physical text would name physical
objects, and no consumer needs them (a quack client builds its own view SQL from the name alone).

**A number that describes the physical object is not an answer about the virtual one.** The rule, and
it is the security-relevant half of this spec:

| column | answer |
| --- | --- |
| `estimated_size` | NULL — the physical row count is not the principal's row count |
| `column_count` | recomputed from the visible columns |
| `database_oid`, `schema_oid`, `table_oid`, `view_oid`, `oid`, `parent_schema_oid` | NULL — identifiers of physical catalog entries |
| `index_count`, `check_constraint_count`, `has_primary_key` | NULL — properties of the physical table |
| `internal`, `temporary` | `false` — a virtual object is neither |
| `comment`, `tags` | the virtual object's own comment; tags empty |
| `path` (`duckdb_databases`) | NULL — a file path is the physical database |
| `data_type` and friends (`duckdb_columns`) | the physical column's, except where a grant's projection replaced it |

**One row per column, whatever the roles overlap on.** A principal may hold several roles, and two of
them may project the same name — at the same position or at different ones. The projection CTE
de-duplicated by `(catalog, object, name, type, position)`, so two roles that named the same column at
different positions produced **two rows**: `column_count` off by one and, worse, a synthesized DDL of
`CREATE TABLE "orders"("id" INTEGER, "tag" VARCHAR, "amount" INTEGER, "tag" VARCHAR)` — invalid SQL,
in the one string a client parses. It now collapses to one row per name, keeping the lowest position
and the type that goes with it.

The comment is the one that changes an existing answer: `information_schema.tables` used to carry the
**physical** table's comment, which describes an object the role is not reading and may say things
about it that the ACL hides. It is now the virtual object's own comment, on both surfaces. A live
schema alias keeps the physical comment, because a schema alias is the physical schema shown live —
that is what it is for.

## Enforcement & security

- **Nothing physical appears.** A listing may name only virtual catalogs, virtual schemas and virtual
  names; the physical facts in the table above are nulled rather than borrowed. The existing filters
  — an object is listed when a role holds something on it, a column when the grant's column list keeps
  it — are unchanged, so *which* rows appear does not move in this spec, only what each row says.
- **The synthesized DDL cannot describe more than the principal reads**, because it is generated from
  the same effective-columns listing that the columns surfaces use. A hidden column is absent from all
  three answers or from none.
- **Fail-closed is unchanged.** A policy source that cannot enumerate still refuses (memory mode
  returns false and the rewriter denies; the function driver throws with the reason). The surface
  names stay reserved, so a virtual object cannot take one and become listed-but-unreachable.
- **No new query parameters**: the listings are constant SQL built by the store, as they are today.

## Testing

`test/sql/acl_metadata_shapes.test` (new, 420 assertions):

- **Shape, per surface.** For each of the eight names: the column names and types under a principal
  equal those of the real surface on an unprefixed connection. Driven by `DESCRIBE`, so the assertion
  is the whole shape rather than the columns someone remembered.
- **The quack catalog load query verbatim** — `SELECT schema_name, sql, 'table' FROM duckdb_tables()
  UNION ALL SELECT schema_name, view_name, 'view' FROM duckdb_views()` — returns the principal's
  objects. This is the regression test for the defect that motivated the spec.
- **`duckdb_views()` answers about views**, with `view_name` populated and table rows absent.
- **The synthesized `sql` is valid and faithful**: it parses, and the column names and types it
  declares equal those `DESCRIBE <name>` gives for the same principal.
- **A hidden column is hidden everywhere**: absent from `duckdb_columns()`, from
  `information_schema.columns`, from the synthesized `sql`, and from `DESCRIBE`.
- **A masked column's type follows the mask** (spec 026) in `duckdb_columns().data_type` and in the
  synthesized DDL alike.
- **No physical fact leaks**: `estimated_size`, the oids and `path` are NULL; `sql` names the virtual
  object and does not contain the physical one.

- **A grant's own projection, three ways.** A second role reads `orders` as `(id, initial =
  tenant[1])`: the columns listing, the synthesized DDL and `DESCRIBE` all say `id INTEGER, initial
  VARCHAR`, and none of them mentions `tenant`. This is the case that proves building all three from
  one listing was the point.
- **A live schema alias** goes through the same surfaces: virtual catalog, virtual schema, right
  column count, a DDL naming neither the physical schema nor the physical database.
- **Competing roles.** A JWT carrying two roles whose column lists overlap (`id` in both) and which
  project the same name at *different positions*: every column appears exactly once and
  `column_count` is 3. And where two roles project the same name with *different expressions* — which
  the read path refuses outright, since there is no order on expressions — the listing still shows one
  row per name, and reading the object still fails with the same error.

Existing coverage (`acl_metadata.test`, `acl_show_surface.test`, `acl_columns_restrict.test`) pins the
row-level behaviour and passes unchanged. One expectation moved, correctly:
`acl_virtual_catalog.test` asserted `count(*) FROM duckdb_tables()` = 5 for a catalog of four tables
and one view, because both questions were answered from one listing. It is now 4, with a companion
assertion that `duckdb_views()` answers `recent`.

Whole suite: 37 files, 2997 assertions, plus both C++ binaries.

## Alternatives considered

- **Leave the collapse and tell consumers to use `information_schema`.** We do not control the
  consumers: quack's catalog loader, the Flight SQL metadata RPCs and every BI tool ask the way they
  ask.
- **Return the physical `sql`.** It names the physical object — a leak — and describes columns the
  principal may not read.
- **Synthesize a `CREATE VIEW` instead of a `CREATE TABLE`.** A client that binds the DDL to learn the
  column types needs a table definition; a view body would have to name real objects.
- **Hand-write eight queries.** They would drift the first time one is edited; the surface table plus
  one code path is the same amount of SQL with one place to change.

## Follow-ups

- The surfaces still denied outright (`duckdb_constraints`, `duckdb_indexes`, `duckdb_functions`,
  `duckdb_types`, …) stay denied. Each is its own question, and the leak audit owed after the servers
  is where the inventory belongs.
- **A virtual table function is callable but undiscoverable.** Verified: a principal runs
  `SELECT * FROM by_tenant('acme')` and gets its rows, while the function appears in no listing —
  `duckdb_tables()` and `duckdb_views()` do not carry it (it is a parameterised relation, not a
  table), `duckdb_columns()` has nothing for it, and `duckdb_functions()` is denied. So a client or an
  agent that browses the catalog cannot learn that it exists, let alone its signature. Closing that
  means a filtered `duckdb_functions()` with the function grants' visibility rules and the declared
  signature — its own spec, and the one metadata gap this one deliberately does not touch. Note that
  neither door's catalog has a place for it either: quack loads tables and views only, and Flight
  SQL's metadata is catalogs/schemas/tables/columns/keys. Whatever we expose, discovery of a
  parameterised relation will not arrive through a standard catalog RPC.
- NULL oids are honest but unusual; a client that keys on them will see NULLs. If one turns up,
  synthesizing stable per-listing ids is a small change.
- `is_insertable_into` is still borrowed from the physical row, so a read-only virtual object may say
  `YES`. Making it follow the grant's capabilities is worth doing with the writability work, not here.
- `information_schema.columns` has 45 columns and most of them will be NULL for a synthesized row.
  That matches what duckdb itself returns for most of them.
- ~~**Column order under multiple roles is not pinned, on either side.**~~ Fixed by **spec 036**: the
  read path merged roles in store order and the listing computed its own order from positions, so for
  two roles the DDL said `(id, tag, amount)` while `DESCRIBE` said `(id, amount, tag)`. That matters
  more than it looks, because quack's scan projects *positionally*
  (`query += "#" + to_string(col_id.GetPrimaryIndex() + 1)`) against a client-side catalog built from
  this DDL. Both sides now order by *(first role naming the column, in role-name order; its position
  in that role's list)*.
- **An object whose roles conflict is still listed.** Two roles masking one name differently make the
  whole object unreadable (`SELECT`, `SELECT *` and `DESCRIBE` all refuse), yet it appears in the
  listings — one row per column now, but describing something nobody can read. Excluding it would
  need the listing to compare the grants' *expressions*, which `grant_columns` does not store; the
  honest fix is either to store them or to make the conflict impossible where the grant is written.
- **A type only the server knows makes the DDL unbindable for a client.** The synthesized `sql`
  emits `data_type` verbatim, so a column whose type comes from a loaded extension — the mssql
  scanner's `MSSQL_VARCHAR` / `MSSQL_NVARCHAR`, which it can be told not to surface — would produce a
  `CREATE TABLE` that a plain duckdb cannot parse. Probed locally, two neighbouring cases are safe: a
  duckdb alias type (`CREATE TYPE code AS VARCHAR`) is already resolved to `VARCHAR` by
  `information_schema.columns`, and an `ENUM` is inlined as `ENUM('a', 'b')`, which any duckdb binds.
  The extension-type case could not be probed here (it needs an mssql-backed catalog) and is the one
  to verify when the quack door is built — together with **what a quack client does when the catalog
  DDL names a type it does not know**, which is worth asking upstream before quack ships rather than
  after. Whether the answer is to normalise the type, to require the scanner's flag, or to leave it,
  it is a decision for that spec: the Flight SQL path asks the same question one layer down, where
  duckdb's own Arrow type-extension machinery may already answer it.
