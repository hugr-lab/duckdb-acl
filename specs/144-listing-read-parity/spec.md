# Spec 144: a listing says what the read returns - live aliases, struct paths, star filters

- **Status**: implemented
- **Date**: 2026-10-23
- **Author**: hugr lab (found by spec 143's reviews; accepted by the owner 2026-10-23)

## Summary

Spec 035's rule is that a principal's listings describe exactly what its reads return. Spec 143's reviews found
two places where they do not - a live schema alias's columns ignore a narrowing grant, a catalog grant's struct path
leaves the hidden fields in the listed type - both listing names the read hides (and, since spec 143, their comments,
tags and the Flight `REMARKS`). A third, of the same family but no leak: `SELECT * LIKE '…'` under a principal reads
the right columns and names every one of them after the pattern. This spec makes all three follow the read.

## Problem

1. **A live schema alias under a narrowing grant.** `CREATE VIRTUAL SCHEMA c.raw AS phys.main` plus `GRANT CATALOG c
   TO ROLE r … COLUMNS (id, amount = 0)`: `SELECT * FROM raw.orders` returns `id, amount` (the read applies the
   catalog grant's list and an object grant's on `raw.orders`, `RowPolicy`'s two levels), while
   `information_schema.columns` / `duckdb_columns` / GetTables' schema list `note` as well - its name, type, comment
   and tags. The listing's alias leg takes the physical columns whole: "visibility is the schema's".
2. **A catalog grant's struct path.** `GRANT CATALOG c … COLUMNS (id, addr.city)` reads `addr` as
   `STRUCT(city VARCHAR)`, and lists it as the source's `STRUCT(city VARCHAR, secret VARCHAR)` - the hidden field's
   name in the listing and in Flight's promised schema. The same path on an object grant is listed right: its
   projection is probed into `grant_columns` (spec 026), a catalog grant's is not, and only the projection's rows
   pass through `acl_listed_type` (spec 102).
3. **`SELECT * LIKE '%t%' FROM t`** under a principal reads the right columns - duckdb expands the star over the
   rewritten FROM, so the pattern matches the virtual names of the visible columns (`* LIKE 'p%'` over `COLUMNS (id,
   paid = amount)` reads `paid`, never the source's `amount`) - but every column is named `(* ~~ '%t%')`, where
   duckdb names them `tenant, amount, …`. `KeepItemNames` (spec 072) gives an item without an alias its current name;
   duckdb turns `* LIKE` / `ILIKE` / `SIMILAR TO` (and their `NOT`) into `COLUMNS(list_filter(*, …))` carrying that
   alias. Names only - nothing the read hides is reached.

## Design

- **Alias leg visibility** (`MetadataListingSql`): an alias object's column is listed when, for some role holding the
  catalog, the catalog grant's list and the role's object grant on that object (`role_object_caps`, the object's
  key under the alias) both keep it - `RowPolicy`'s two levels, read the way spec 143's re-review made the listing
  read every list (`ParseColumnList`, a constant per stored list). No list of the principal's names anything: the
  leg stays as it is (the common case costs nothing).
- **Struct paths and masks in a listed type**: a column some stored list narrows by a path (`addr.city`,
  `items[].price`) or masks is listed through `acl_listed_type` with the roles' lists (`roles_of`, as the projection
  leg already does) - on the relation legs and the alias leg alike; any other column keeps its listed type. Which
  columns are so is read with the lists, in C++. A mask nothing probed (a catalog grant's; an object grant's on a live
  alias's object) is typed as its text says - a constant's type, a cast's target - else, for a mask that reads
  columns, the source's type where that is no nested type, else NULL: never a nested source type, whose field names
  the grant may hide (the review's finding: a field fallback listed them).
- **A column the levels leave nothing of** (`addr.city` at one level, `addr.secret` at the other) is no column of the
  read: `acl_listed_type` answers NULL and the row drops - on the projection leg too, which used to fall back to one
  role's probe and so named the other level's hidden field.
- **Positions close up** where a list narrowed anything: `ordinal_position` / `column_index` are renumbered per object
  in the listing's order (spec 036; a catalog grant's list left holes on relations already).
- **A list of nothing but separators** (`COLUMNS (,)` stores `' , '`) narrows nothing, as the read reads it - the
  listing used to keep nothing.
- **An object a relation names under an alias path** (`CREATE VIRTUAL TABLE c.raw.orders AS …` where `raw` is a live
  alias) is that relation's - the read resolves the relation first - and the alias legs leave it out (it was listed
  twice, with the shadowed table's columns).
- **Expanding items keep duckdb's names**: `KeepItemNames` leaves alone an item with a star anywhere in it - `* LIKE
  '…'` (duckdb's `TryTransformStarLike` turns it into `COLUMNS()`), `1 + COLUMNS('a|b')`, `min(COLUMNS(*))` - but the
  argument of `COUNT(tbl.*)`, which duckdb rewrites into one count (its `FindStarExpression` walk): duckdb names each
  expanded column, and carries an alias onto every one of them.
- **Cost**: the alias leg narrows only when the principal holds a catalog grant's list or an object grant's list on
  an object no relation names, read in C++; the object level is a joined column, never a subquery as a `CASE`
  operand (the first cut's planner cost grew with the number of distinct lists: 40 lists 26 s, 500 never finished).
  Measured, 40 relations each under its own object grant list, one table's columns: 0.54 s (main 0.48 s; the
  renumbering is ~0.08 s).
- **Which grant rows narrow**: spec 145 (a capability's policy is the union of the grants that hold it) - the
  listings take its rule for reads, the rows holding `select`, when it lands.

## Enforcement & security

- Only listings change; the read path is untouched. Each change removes from a listing what the read does not
  return (1, 2) or names a column as the read names it (3).
- A list that cannot be read (a list written after the listing composed its constants) keeps nothing - fail closed,
  as spec 143's split does.

## Testing

- sqllogictest `acl_listing_read_parity.test` (new): a live alias under a catalog grant's list, under an object
  grant's on one alias object, under both, under two roles (a token naming both; one unrestricted); a catalog grant's
  struct path on a relation and on an alias object, a masked field, an object grant's path (unchanged); levels whose
  paths leave nothing of a column; masks typed from their text (`= NULL`, `= 0`, a whole struct masked); positions
  closing up; a separators-only list; a relation declared under an alias path; `SELECT * LIKE`, `NOT LIKE`, `ILIKE`,
  `SIMILAR TO`, `count(t.*)`, `1 + COLUMNS('a|b')` under `ACL ROLE` - each listing compared with what the read
  returns.
- Flight e2e (`run.sh`): GetTables' promised schema for a live alias object under an object grant has the read's
  columns.

## Alternatives considered

- **Probing alias objects' projections at write time** (like spec 026): the alias's objects are the source's, live -
  a table created later has no probe; the listing reads what the policy says instead.
- **Dropping `KeepItemNames` for every item containing a star**: `struct_pack(*)` is one column, and its header
  must stay the call as written.

## Follow-ups

- Spec 145: a role that may not read (only `insert`, `CAPS '{}'`) lifts another role's read policy - the read path,
  found by this spec's review; then the listings' rows narrow by `select` too, and a live alias object under an
  object grant `CAPS '{}'` (still listed) or a `CAPS '{}'` schema grant over a readable object (hidden) follow it.
- The read path (found by the review, its own spec): a catalog grant's struct path fails the read of an object that
  lacks the column (`Column "addr" in REPLACE list not found`) - and such an object stays listed.
- The grammar loses the quotes of a dotted column head in a path (`"we.ird"."a.b"` stored as `we.ird."a.b"`); the
  function form keeps them.
- A mask that reads columns, nothing probed for it, is listed with its source's scalar type or NULL - not its own.
