# Spec 137: a relation's physical name is stored whole

- **Status**: implemented (accepted by the owner 2026-10-19: «Принимаем 137»; the design was narrowed by review
  137, see "What the review found")
- **Date**: 2026-10-19
- **Author**: Claude (with the owner)

## Summary

A virtual table over a two-part physical name (`CREATE VIRTUAL TABLE c.t AS pg.orders`) is read correctly but is
missing from every listing: the listings join an object to its physical row by three parts. From now on a relation's
physical name over an attached database is stored whole, as `<database>.<schema>.<object>`, by what duckdb finds
in that database at write. A name already stored in two parts is found by `acl_check_catalog`, which gives the
statement that repairs it. Nothing is rewritten by itself.

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

## Design

### At write: the object as duckdb finds it in the attached database

`PolicyStore::SpellRelationPhysical` is used by the writers of a relation's physical name:

- `acl_add_relation` (and the grammar over it), `acl_register_created` / `_existing` (spec 113);
- `acl_grant_table` (legacy), and `acl_alter_relation`'s `phys` (`SET PHYS`).

A schema alias's path (`<db>.<schema>`) keeps `SpellPhysical`: it is a schema, not a relation. The memory store,
which lists nothing, keeps every name as written.

`PhysicalObjectReadings` reads a two-part name `a.b` on a fresh connection, from the parts as written:

- **`a` an attached database** (a hidden one too; not `system`, not `temp`, which duckdb reads through its search
  path).
  - The object is looked up as duckdb looks it up: `Catalog::GetEntry` with the catalog and no schema, that is the
    search path's schema for that catalog, else its default.
  - It is stored by the names the catalog gives the entry: `pg.public.orders`, MySQL's `my.acltest.orders` (MySQL
    answers to `main` with its own database), SQL Server's `default_schema` option or `dbo`.
  - An object not there yet takes the default schema's real name. The name is spelled once, after the reading.
- **`a` also a schema of the node's default database**: refused as ambiguous, naming neither reading (a principal
  may not learn the node's default database). duckdb refuses that name at read.
- **`a` only a schema of the node's default database**: kept as written. That database is the node's own (a
  file-backed default is named after its file), and a policy catalog other nodes share must not carry one node's
  name.
- **Neither, or a source that cannot say** (it throws): kept as written. A write does not require its source to bind
  yet; once it binds, `acl_check_catalog` finds the two parts (below).

`CREATE … IF NOT EXISTS` over an existing object skips before the name is read.

### Already stored: found, never rewritten

`acl_check_catalog` adds the finding `phys_incomplete` for a relation whose stored physical name has two parts and
reads as an attached database's object, as above. It names what the name binds to now, and gives the repair:

```sql
ACL ADMIN ALTER VIRTUAL TABLE c.two SET PHYS src.main.t;
```

The owner's rule holds: nothing is rewritten by itself, and an explicit command does the repair. Until it is
repaired, the object stays missing from the listings, as it is today. A read keeps working. A name read in the
node's default database is not reported: its whole name would be one node's.

### The readers

New writes give every reader three parts. The two-part branches stay for the rows not yet repaired, so that
nothing that works today stops working.

## Enforcement & security

- **No change to what a principal may read.** The rewrite of a read emits the stored name, as before. A stored
  whole name is the entry duckdb found for the two-part one at write.
- **The ambiguous case is refused at write**, instead of being left for duckdb to refuse at every read.
- **Source grants (spec 118.3).** `AuthorizeSources` judges the statement as written, before the admin function
  expands the name.
  - A definition's two-part name is judged by the same reading the write stores: `SourceGranted(db, …)`. A catalog
    admin granted `pg.public` may write `pg.orders`, and one granted `src.other` is refused `src.t`
    (`src.main.t`).
  - A name that reads two ways is refused by the gate, naming neither reading; a name whose source could not say
    (the lookup threw) is refused too, never guessed as `main`.
  - **A body's names are judged as written, and narrowed by the reading.** A body's names include those inside a
    physical view, which duckdb binds in the view's own catalog. Reading them against the node's default database
    let a catalog admin build over a view of an ungranted source; review 137 found it. So the plain reading (two
    parts in `main`) must pass, AND for an attached database what duckdb finds there must be granted too: a grant
    on a schema literally named `main` never admits `pg.orders`, which reads `pg.public.orders` - a gap older than
    this spec, closed with it.
- **TOCTOU.** The gate reads the name when the statement is parsed, and the write reads it again when it runs. An
  operator's ATTACH, DETACH or CREATE SCHEMA in between can make the two differ. Only operator actions can do that,
  and the gate had the same gap before.

## What the review found

Three passes covered binding semantics, security and compatibility. All of the following were fixed before the
merge:

- **First version stored the default database's reading.** `s.t` became `<default db>.s.t`. That broke a shared
  policy catalog on every other node, and broke the system catalog's names (`main.duckdb_tables`,
  `system.pg_class`).
- **It took `GetDefaultSchema()` instead of the entry it finds.** On MySQL that stored `my.main.orders`, a name
  MySQL refuses.
- **The gate read body names against the default database.** That was a new hole: the case of a name inside a
  physical view.
- **The ambiguity refusal fired before `IF NOT EXISTS`.**
- **Smaller fixes:** the memory store expanded names; spelling ran before reading; the ambiguity message showed
  the default database's name (to a catalog admin, and through a principal's own CREATE to any role); a hidden
  database was not counted; the gate guessed `main` when the lookup threw.
- **The re-verification pass** confirmed every item above closed, and found the body-name gap below the gate's
  `main` guess (closed here, see Enforcement).

Accepted as they are:

- The TOCTOU above.
- The legacy `acl_grant_table` rows in its implicit catalog `default` are not checked. That is spec 039's existing
  limit: the check walks the stored catalogs.

## Testing

- **sqllogictest** (`test/sql/acl_two_part_phys.test`):
  - `src.t` stores `src.main.t`, and the object is listed in `information_schema.tables`, `columns` and
    `duckdb_tables()`; `SET PHYS src.t2` stores three parts.
  - A schema of the default database (`loc.lt`) is kept as written and not reported.
  - A row stored in two parts gives `phys_incomplete` with its repair, the check changes nothing, and the repair
    makes the object listed.
  - Source gate: a catalog admin granted `src.other` is refused `src.t`; the ambiguous name's refusal names
    neither reading.
  - Gate coverage probe: a view over `sec.main.v` (a physical view over `main.secret`) is refused to a catalog admin
    granted the default database's `main`.
  - A name that reads two ways is refused; `IF NOT EXISTS` over an existing object skips; the whole name is taken
    as written.
- **Existing tests keep the two-part branches covered** by a row written in two parts (`platform_effective_rights`)
  and a body form (`platform_review`).
- **Integration:**
  - Postgres: `pg.orders` stores `pg.public.orders`, is listed and read, and a catalog admin granted `pg.public`
    writes it; gate coverage probe: one granted a Postgres schema named `main` is refused a body over `pg.orders`.
  - MySQL: `my.orders` stores `my.acltest.orders`, is listed and read.

## Alternatives considered

- **Read-side normalisation in the listing:** a CTE that maps each stored two-part name to its three parts, using
  each database's default schema at listing time. It fixes the listing for old rows too, but every other reader
  keeps its own guess.
- **A migration step that rewrites stored names.** It goes against the owner's rule: nothing changes by itself.
- **Refusing two-part names at write.** That needlessly breaks a form that works and that people write.
- **Copying the binder's rule by hand** (the first version). It differed from duckdb in the cases above. The
  catalog's own lookup is the rule.

## Follow-ups

- **The source gate's other gaps, found by review 137 and older than it** (a spec of their own, before the release):
  - a physical view's own name in a body is never judged, since name extraction does not record a view;
  - a one-part name in a body is matched against a database granted whole;
  - `NamesPolicyStore`'s two-part branch assumes `main` for the policy database.
- A schema alias written with one part (`CREATE VIRTUAL SCHEMA c.s AS pg`) needs the same check.
