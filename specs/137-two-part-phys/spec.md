# Spec 137: a relation's physical name is stored whole

- **Status**: draft
- **Date**: 2026-10-19
- **Author**: Claude (with the owner)

## Summary

A virtual table over a two-part physical name (`CREATE VIRTUAL TABLE c.t AS pg.orders`) is read correctly but is
missing from every listing: the listings join an object to its physical row by three parts. From now on a relation's
physical name is stored whole, as `<database>.<schema>.<object>`, resolved at write the way duckdb binds the
two-part name. A name already stored in two parts is found by `acl_check_catalog`, which gives the statement that
repairs it. Nothing is rewritten by itself.

## Problem

Found by review 136. It is older than that spec.

```sql
ACL ADMIN CREATE VIRTUAL TABLE c.two AS src.t;         -- stored phys: src.t
ACL ADMIN CREATE VIRTUAL TABLE c.three AS src.main.t;  -- stored phys: src.main.t
```

- `ACL ROLE r SELECT * FROM two` works: the rewriter emits `src.t`, and duckdb binds it.
- `information_schema.tables`, `SHOW TABLES` and `duckdb_tables()` list `three` and not `two`. The Flight
  `GetTables` RPC does the same, since it reads `information_schema.tables`. The tables surface requires
  `len(parts) = 3`.
- `information_schema.columns` lists `two`'s declared columns when it has a list, but never its physical columns.
- Other readers of a stored name each guess what two parts mean:
  - the listing's source keys assume `<db>.main.<t>`;
  - `physcols` (spec 039's broken mark) reads `src.t` as schema `t`;
  - the source grants (`SourceGranted`), `platform.effective_rights` and lineage each have their own two-part
    branch.
  - The guess is wrong for a Postgres source, whose default schema is `public`.
- The read itself is fragile: `src.t` binds to the database `src`, unless the node's default database holds a
  schema named `src`. duckdb then refuses the read (`Ambiguous reference to catalog or schema`).

## Design

### At write: the name as duckdb binds it

`PolicyStore::SpellPhysical` gets a relation form (`SpellRelationPhysical`) for the writers of a relation's
physical name:

- `acl_add_relation`, `acl_register_created` / `_existing` (a principal's own CREATE, spec 113);
- `acl_grant_table` (legacy, catalog mode), and `acl_alter_relation`'s `phys` (`SET PHYS`).

A schema alias's path (`<db>.<schema>`) keeps the two-part form; it is a schema, not a relation.

A two-part name `a.b` becomes three parts by duckdb's own reading:

- `a` is an attached database: `a.<its default schema>.b` (`Catalog::GetDefaultSchema()`: `main` for duckdb and
  DuckLake; `public` for Postgres, or the first schema its ATTACH names; for SQL Server the login's default schema,
  usually `dbo`).
- `a` is a schema of the node's default database: `<default database>.a.b`.
- Both: refused as ambiguous, naming the two three-part names to write instead. duckdb refuses that name at read
  too.
- Neither: written as given. The source probe that every CREATE runs already fails on a name that binds to
  nothing.

A three-part name is unchanged; its parts are still spelled as today. A one-part name is unchanged: it means the
node's default database, and this spec does not touch it.

### Already stored: found, never rewritten

`acl_check_catalog` adds the finding `phys_incomplete` for a relation whose stored physical name has two parts. It
says what the name binds to now, and gives the repair statement:

```sql
ACL ADMIN ALTER VIRTUAL TABLE c.two SET PHYS src.main.t;
```

The owner's rule holds: nothing is rewritten by itself, and an explicit command does the repair. Until it is
repaired, the object stays missing from the listings, as it is today. A read keeps working.

### The readers

New writes give every reader three parts. The two-part branches stay for the rows not yet repaired, so that
nothing that works today stops working.

## Enforcement & security

- **No change to what a principal may read.** The rewrite of a read emits the stored name, as before. A stored
  three-part name binds exactly what the two-part one did at write time, because the expansion is duckdb's own
  reading.
- **The ambiguous case is refused at write**, instead of binding whichever object duckdb finds at read.
- **Source grants (spec 118.3)** judge the three-part name. The expansion happens before `AuthorizeSources`, so a
  catalog admin granted `pg.public` may write `pg.orders`. Its expansion `pg.public.orders` is inside the grant.

## Testing

- **sqllogictest:**
  - `CREATE VIRTUAL TABLE c.two AS src.t` stores `src.main.t`, and the object is listed in
    `information_schema.tables`, `columns` and `duckdb_tables()`.
  - A second attached database with a schema named like the first database: the two-part name is refused as
    ambiguous, naming both three-part names.
  - `ALTER … SET PHYS src.t` stores three parts.
  - A two-part name stored the old way (written straight into the policy table) gives the `phys_incomplete`
    finding with its repair; the repair makes the object listed.
- **Integration (Postgres):** `CREATE VIRTUAL TABLE c.o AS pg.orders` stores `pg.public.orders`, which is listed
  and read.

## Alternatives considered

- **Read-side normalisation in the listing:** a CTE that maps each stored two-part name to its three parts, using
  each database's default schema at listing time. It fixes the listing for old rows too, but every other reader
  keeps its own guess, and the read stays fragile.
- **A migration step that rewrites stored names.** It goes against the owner's rule: nothing changes by itself.
- **Refusing two-part names at write.** That needlessly breaks a form that works and that people write.

## Follow-ups

- A schema alias written with one part (`CREATE VIRTUAL SCHEMA c.s AS pg`) needs the same check.
