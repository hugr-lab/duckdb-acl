# Spec 144: a listing says what the read returns - live aliases, struct paths, star filters

- **Status**: draft
- **Date**: 2026-10-23
- **Author**: hugr lab (found by spec 143's reviews; the owner, 2026-10-23: "давай начнём 144")

## Summary

Spec 035's rule is that a principal's listings describe exactly what its reads return. Spec 143's reviews found
three places where they do not: a live schema alias's columns ignore a narrowing grant, a catalog grant's struct
path leaves the hidden fields in the listed type, and `SELECT * LIKE '…'` under a principal names every column
after the pattern. The first two list names the read hides - and, since spec 143, their comments, tags and the
Flight `REMARKS`. This spec makes the listings follow the read in all three.

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
3. **`SELECT * LIKE '%t%' FROM t`** answers `tenant, amount, …` in duckdb and three columns all named
   `(* ~~ '%t%')` under a principal. `KeepItemNames` (spec 072) gives an item without an alias its current name; duckdb
   turns `* LIKE` / `ILIKE` / `SIMILAR TO` (and their `NOT`) into `COLUMNS(list_filter(*, …))` carrying that alias.

## Design

- **Alias leg visibility** (`MetadataListingSql`): an alias object's column is listed when, for some role holding the
  catalog, the catalog grant's list and the role's object grant on that object (`role_object_caps`, the object's
  key under the alias) both keep it - `RowPolicy`'s two levels, read the way spec 143's re-review made the listing
  read every list (`ParseColumnList`, a constant per stored list). No list of the principal's names anything: the
  leg stays as it is (the common case costs nothing).
- **Struct paths in a listed type**: a column some stored list narrows by a path (`addr.city`, `items[].price`) is
  listed through `acl_listed_type` with the roles' lists (`roles_of`, as the projection leg already does) - on the
  relation legs and the alias leg alike; a column no path narrows keeps its listed type (a whole-column mask's type
  stays what spec 026's probe or the source says - `acl_listed_type` has no probe for a catalog mask). Which columns
  a path narrows is read with the lists, in C++.
- **Star filters keep duckdb's names**: `KeepItemNames` leaves alone an item whose root (under one `NOT`) is a
  function with a star as its first argument - duckdb's `TryTransformStarLike` shape, which expands to the columns.
- Not here: a catalog grant's mask that changes a live alias column's type is still listed with the source's type
  (nothing is probed for an alias object, which the policy never names) - a description, not a leak; the follow-up.

## Enforcement & security

- Only listings change; the read path is untouched. Each change removes from a listing what the read does not
  return (1, 2) or names a column as the read names it (3).
- A list that cannot be read (a list written after the listing composed its constants) keeps nothing - fail closed,
  as spec 143's split does.

## Testing

- sqllogictest `acl_listing_read_parity.test` (new): for each - a live alias under a catalog grant's list, under an
  object grant's on one alias object, under both, under two roles (one unrestricted); a catalog grant's struct path
  on a relation and on an alias object, an object grant's (unchanged), a path under a mask; `SELECT * LIKE`, `ILIKE`,
  `NOT LIKE`, `SIMILAR TO` under `ACL ROLE` - the listing (information_schema.columns, duckdb_columns, DESCRIBE)
  compared with the read's columns and types.
- Flight e2e: GetTables' promised schema for an alias object under a narrowing grant has the read's columns.

## Alternatives considered

- **Probing alias objects' projections at write time** (like spec 026): the alias's objects are the source's, live -
  a table created later has no probe; the listing reads what the policy says instead.
- **Dropping `KeepItemNames` for every item containing a star**: `struct_pack(*)` is one column, and its header
  must stay the call as written.

## Follow-ups

- A catalog grant's type-changing mask on a live alias object's column (listed with the source's type).
