# Spec 113: dbt's own statements under the ACL

- **Status**: implemented
- **Date**: 2026-10-09
- **Follows**: specs 016 / 051 (create and drop in a granted schema), 112 (the lineage spikes)
- **Found by**: the dbt spike of 2026-10-09 (dbt-duckdb, the node attached through quack under the
  virtual catalog's name)

## Summary

dbt-duckdb's stock materializations do four things the ACL refuses today, so the spike needed a custom
`acl_table` materialization and a macro that silences `create_schema`. With this spec a stock dbt
project runs unchanged against a schema granted with `create` and `drop`.

## Problem

Measured on the 112 build, as a principal holding `select, insert, update, delete, create, drop` on the
live schema alias `sales.dbt_home` (`AS phys.dbt_home`):

| dbt does | today |
| --- | --- |
| `CREATE SCHEMA IF NOT EXISTS "sales"."dbt_home"` (every run) | refused: "only tables and views can be created through the ACL" |
| `CREATE TABLE "sales"."dbt_home"."m__dbt_tmp" AS (...)` - names are always three-part | refused: "no schema of the catalog allows creating sales.dbt_home.m__dbt_tmp" |
| `DROP TABLE IF EXISTS "sales"."dbt_home"."m__dbt_backup" CASCADE` | refused: "no schema of the catalog allows dropping …" |
| `ALTER TABLE … "m" RENAME TO "m__dbt_backup"`, then `… "m__dbt_tmp" RENAME TO "m"` (table and view materializations swap this way) | refused: "statement type ALTER is not permitted" |

The same names written two-part (`dbt_home.m`) already create and drop, and three-part names already
read, insert and list (`information_schema.tables` answers `sales, dbt_home, m`). Only the DDL home
resolution does not accept the virtual catalog's own name in front.

## Design

1. **Names in DDL: `[<vcat>.]<schema path>.<object>`** - the rule reads already follow, now for
   CREATE / CREATE OR REPLACE / DROP / RENAME / `CREATE SCHEMA IF NOT EXISTS` alike (owner,
   2026-10-09):
   - **The first part is a catalog** when it names a virtual catalog the principal holds a grant on -
     any of them, not only the MAIN one: with several catalogs per role, the three-part name is how
     a statement picks one.
   - **Otherwise the name is a path in the MAIN catalog**, as two-part names are today.
   - **Nested schemas** (duckdb 2.0): the path may be of any depth (`sales.raw.dbt_home.m`). The
     object's home is the longest granted schema prefix - the model of design 004 for capabilities on
     nested schemas. `main` is the catalog's default schema (spec 112's `<vcat>.main.<object>`).
   - **Ambiguity is refused**: a first part that is both a catalog of the principal and a schema of
     its MAIN catalog fails with both readings named - as duckdb's own "ambiguous reference to catalog
     or schema". The same name never lands in different homes depending on the grants.
   - Any other first part is refused as today; never a path to a physical catalog.
   - `CASCADE` is accepted only where the drop stays the one object the capability covers: what
     duckdb's CASCADE would take with it (indexes, dependent entries) is checked during implementation,
     and a drop that would reach any other object is refused.
2. **`CREATE SCHEMA [IF NOT EXISTS] [<vcat>.]<schema>`** where `<schema>` is a virtual schema the
   principal holds any capability on: `IF NOT EXISTS` is a no-op (compiled to a constant `SELECT`,
   audited as `ddl` with the schema as object); without it, the duckdb error "schema … already
   exists". A schema the principal does not hold is refused as today - creating schemas stays the
   operator's (no change to spec 016's model).
3. **`ALTER TABLE|VIEW <name> RENAME TO <new>`** inside a granted schema home, priced at `create` +
   `drop` on that schema (a rename is a drop of the old name and a create of the new one):
   - both names in the same home (duckdb's own rule: RENAME keeps the schema); `<new>` must not
     resolve to an existing virtual object, so a rename never shadows a declared relation;
   - refused when the object is a **declared relation** of the catalog (a `relations` row with its
     own grants or columns, created by the operator) - only objects living in the home by expansion
     or by a live alias are renamed, so no grant is orphaned;
   - an expansion schema (`FROM`) also renames its record (`relations.vname`) in the same transaction;
     a live alias (`AS`) has no record;
   - compiled to the physical `ALTER … RENAME` on the home, executed like spec 016's DDL;
   - every other ALTER stays refused.
4. **Lineage** (spec 112): a rename is a `DATASET` event pair - the old name `DROP`, the new `CREATE`
   - so the backend follows dbt's swap; `__dbt_tmp` / `__dbt_backup` objects are ordinary datasets.

## Enforcement & security

- Nothing reaches beyond what `create` + `drop` on the schema already allow: a rename is expressible
  today as CTAS-to-new + DROP-old under the same capabilities, without the data copy.
- A qualified name resolves only into a catalog the principal holds a grant on, under that catalog's
  grants - never into a catalog it does not hold, never to a physical name; an ambiguous one is
  refused rather than guessed.
- A declared relation keeps its name: its grants, masks and RLS are tied to it.
- `CREATE SCHEMA` never creates anything.

## Testing

- `test/sql/acl_ddl.test`: three-part CREATE / CTAS / CREATE OR REPLACE / DROP [IF EXISTS] [CASCADE]
  in the MAIN catalog and in a second catalog of the role; a nested path (longest granted prefix); an
  ambiguous first part refused; a first part the role holds no grant on refused;
  CREATE SCHEMA IF NOT EXISTS (held, not held, without IF NOT EXISTS); RENAME of a table and a view in
  a live alias and in an expansion (the record follows), refused for a declared relation, for a
  target name that exists, across schemas, without `drop`; every other ALTER still refused.
- Lineage: the rename's DROP/CREATE pair.
- The dbt spike with the **stock** `table`, `view` and `incremental` materializations and no macros.

## Alternatives considered

- **Keep the custom materialization** (`acl_table` in the spike): every dbt user would have to carry
  it, and `view` / `incremental` / snapshots need their own.
- **Rename as CTAS + DROP inside the node**: copies the data; the physical RENAME is the same
  capability without the copy.
- **Resolve three-part names only against the MAIN catalog**: breaks a role with several catalogs and
  collides with nested schemas (`a.b.c` is also a path in MAIN).
- **Let a principal create schemas**: a new capability and a new home model; dbt only needs the
  schema to exist, so a no-op on a held schema is enough.

## Next, its own spec: the session's default catalog

A client should be able to say, for its session, which virtual catalog counts as its main one -
`USE sales` / `USE sales.dbt_home` under a principal (and the same through a door's session
options), so short names resolve there instead of in the role's MAIN catalog. Rules to settle there:

- only on a session of the client's own (spec 068's `Principal::session_connection`): on a gateway's
  shared connection it would leak to the next principal;
- only a catalog (and schema) the principal holds a grant on; the role's MAIN stays the default;
- it changes only how a short name resolves - never what is granted - and the ambiguity rule above
  still applies;
- Flight `SetSessionOptions` (`catalog` / `schema`, as ADBC/JDBC send them) map to it; for quack,
  where a client's `USE` is its own local catalog, the channel is to be found (a session setting).

dbt does not need it (it qualifies every name), which is why it is not part of this spec.

## Out of scope

- Spark's `truncate` (JDBC `TRUNCATE TABLE`, needs a JDBC dialect in acl-clients) - a client recipe.
- dbt snapshots (MERGE-based) and `incremental` strategies beyond append / delete+insert / merge are
  checked in the spike, not designed here.

## As built

- **Names.** `CatalogBackend::DdlTarget` reads `[<vcat>.]<path>.<object>`: rows of both readings are
  fetched, a name both fit is refused (`… is ambiguous - catalog … or schema …`), the longest granted
  prefix of the chosen reading is the home, and `DdlTarget::vname` is the object's name inside its
  catalog - what records, conflicts and drops use (the written name only names the audit object).
  `HeldSchema` is the same rule for `CREATE SCHEMA` (a schema names itself whole: exact path).
- **CASCADE** is taken off the physical DROP (`info.cascade = false`): duckdb's own CASCADE takes no
  other entry (a view over the table stays, a referencing FK refuses), but a home in another engine
  would drop its dependents there.
- **No-op batches.** A batch whose every statement became a no-op (`CREATE SCHEMA IF NOT EXISTS`, a
  taken `CREATE … IF NOT EXISTS`) used to reach the client as no statement at all - the quack client
  fails "Query did not return any columns". It is now one empty `SELECT`.
- **RENAME.** `RewriteAlterStatement`: RENAME TABLE / RENAME VIEW only; the old name's `drop` home and
  the new name's `create` home must be the same schema row; a view record renames its record
  (`acl_rename_relation`, nothing physical); a table renames physically, then its record if it has
  one. "Taken" is a catalog record only: dbt swaps inside its own transaction, which a look from the
  store's connection does not see - the physical clash is the native ALTER's own error, judged in the
  client's transaction. `CatalogRelationDeclared`: a predicate, relation columns, keys, references,
  an object grant or grant columns on the name.
- **Spike (2026-10-09, dbt-duckdb through quack, no macros but `generate_schema_name`):** `table` and
  `view` materializations created and swapped on every run; `incremental` with `append` works; with a
  `unique_key` (delete+insert) the quack client fails with `PlanDelete not implemented` before the
  node sees anything - a client limitation, documented.
- **Lineage test for the rename pair** lands with the rebase onto spec 112 (its names).
