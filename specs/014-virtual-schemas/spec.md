# Spec 014: virtual schemas as objects — alias, expansion, refresh

- **Status**: implemented
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

A virtual schema is currently one row of `schema_aliases`: a prefix that resolves to a physical
schema and nothing else — no comment, no way to exclude a single table from it, no record that it
exists at all beyond the prefix match. This spec makes a schema an object of the catalog: it can be
documented, it can be created two ways — a **live alias** (`AS`, resolves through, sees new physical
tables immediately) or an **expansion** (`FROM`, materialises a virtual record per object, each of
which can then be altered, dropped or granted separately) — and an expansion can be re-read with
`REFRESH` when the source grows.

This is part 2 of design 004. Part 3 (schema-level grants and their materialised caps inheritance)
needs schemas to be objects before a grant has anything to attach to.

## Problem

- **A schema cannot be documented.** Spec 010 gave comments to relations and functions; a schema has
  nowhere to put one, because there is no row that means "this schema exists" — only a prefix rule.
- **A live alias is all-or-nothing.** `sales.raw` mapped onto `pg.public` exposes every table in that
  physical schema, forever, including ones created later. There is no way to say "all of them except
  `secrets`", short of not using an alias at all and registering each table by hand.
- **Nothing records where a registered table came from**, so there is no way to ask "the source grew
  — what is new?" other than diffing by hand.

## Design

### One table for schemas

`acl.schemas(vcat, path, phys_path, origin, comment)` replaces `acl.schema_aliases`, whose rows
migrate into it (schema v4, in place; the legacy table is kept in step for one version so a rollback
still resolves). `phys_path` carries the two kinds, and `origin` remembers an expansion's source:

| `phys_path` | kind | what it means |
| --- | --- | --- |
| non-NULL | **alias** | resolves through the prefix, live: a table added physically is visible at once, and nothing can be excluded |
| NULL | **expansion / own schema** | the schema exists as a name; what is visible inside it are the catalog's own relation records |

Resolution is unchanged in shape: the alias lookup reads the rows that carry a `phys_path`, so the
same query serves both catalog and function-driver modes (the driver contract keeps its
`schema_aliases` slot — a platform expresses aliases, not comments).

### Two ways to create one

```sql
CREATE VIRTUAL SCHEMA sales.raw AS phys.main [COMMENT 'raw layer, as-is'];   -- live alias
CREATE VIRTUAL SCHEMA sales.curated FROM phys.main [COMMENT 'curated tables']; -- expansion
DROP VIRTUAL TABLE sales.curated.secrets;                                     -- now possible
```

The expansion reads the physical catalog **at write time** (`duckdb_tables()` / `duckdb_views()` for
that database and schema, the same way the schema probe of spec 010 reads it) and writes one
`alias`-form relation per object, named `<schema>.<object>` inside the virtual catalog. Each record
keeps its `origin` (the physical schema it came from), which is what makes the next part possible:

```sql
ALTER VIRTUAL SCHEMA sales.curated REFRESH;            -- add what appeared
ALTER VIRTUAL SCHEMA sales.curated REFRESH PRUNE;      -- and remove what is gone
```

`REFRESH` adds objects that exist physically and have no record yet; it never rewrites an existing
record, so one an admin changed is safe by construction. A record dropped on purpose is remembered in
`acl.schema_dropped` and not re-added — excluding one object is the whole reason to expand rather
than alias, and a refresh that undid it would make the choice pointless. Re-running the expansion
forgets those tombstones: the admin asked for the source as it is now. `PRUNE` removes records whose
physical object is gone, and only ones the expansion itself produced (`origin` says which) — what an
admin registered by hand inside the schema is theirs. Both report how many rows they changed, and a
second refresh over an unchanged source reports 0. A **live alias** answers `REFRESH` with an error
rather than pretending: it has nothing to refresh, since it already shows what the source holds.

Redefining an expanded record is two different intentions, and they behave differently: `ALTER`
tweaks a property and **keeps** the record part of the expansion (so `PRUNE` still removes it when
its source is gone — it would otherwise point at nothing), while `CREATE OR REPLACE` says "this
object is mine now" and takes it out. Expanding a source that does not exist is refused: it would
leave a schema that can never resolve anything.

Consequences, deliberately:

- an expansion is a **snapshot plus edits**, so a table created physically after it is invisible
  until `REFRESH` — that is the point of choosing it over an alias;
- an alias is **live and total**; if a single object must be excluded, the schema has to be an
  expansion. Nothing about this is dynamic-with-exceptions, because "exceptions" would be a deny
  list, and this model has no deny lists (spec 011: a grant narrows, it never blacklists).

### Dropping

`DROP VIRTUAL SCHEMA sales.curated` removes the schema row. Its expanded records are relations of
the catalog in their own right, so they are removed only with `CASCADE`, and the statement otherwise
fails naming how many would be orphaned — the same rule `DROP VIRTUAL CATALOG` already follows for
grants (spec 010).

## Enforcement & security

A schema row is not a grant: making one changes what names *resolve*, not what a role may do — the
capability still comes from the catalog grant (and, after part 3, from the schema grant). An
expansion cannot expose more than an alias would: it registers exactly what the source has at that
moment, in `alias` form, so every read still goes through the relation path and its capability check.
Reading the physical catalog happens on the write path only, so a principal's query never triggers it.

## Testing

`test/sql/acl_virtual_schemas.test` (80 assertions): an alias and an expansion over the same physical schema; the
alias seeing a table created afterwards while the expansion does not until `REFRESH`; `REFRESH`
reporting its count, leaving an admin-modified record alone and not resurrecting a dropped one;
`PRUNE` removing a record whose source is gone; a single object excluded from an expansion and denied
while its neighbours resolve; comments on both kinds, surviving an `ALTER`; `DROP` refused while
records exist and `CASCADE` taking them; a view in the source expanded like a table and read through;
a name redefined with `CREATE OR REPLACE` leaving the expansion while an `ALTER`ed one stays in it;
a source that does not exist refused; and the migration — a catalog written by the previous version
keeps resolving its aliases.

## Alternatives considered

- **A second table for expansions**, leaving `schema_aliases` alone: two tables that answer the same
  question ("does this schema exist?"), and every reader would have to consult both.
- **Alias with an exclusion list**: a deny list by another name, and the one thing this model refuses
  to have — every other narrowing here is a positive list.
- **Expanding at read time** (re-listing the source per query): the write path already owns every
  change, and a per-query catalog listing is exactly the cost spec 010 avoided for probes.

## Follow-ups

- Every `INSERT` into `relations` and `schemas` now names its columns: `ADD COLUMN` appends, so a
  fresh catalog and a migrated one have different column orders, and a positional insert would have
  put values in the wrong fields. Worth remembering for every future migration.


- `CREATE VIRTUAL CATALOG sales AS|FROM pg` — the same two kinds one level up; the mechanics are
  identical and the storage is already there.
- Part 3: `GRANT SCHEMA … WITH (…)`, `role_schemas`, and the materialised caps inheritance whose
  hooks live in the schema DDL this spec adds.
