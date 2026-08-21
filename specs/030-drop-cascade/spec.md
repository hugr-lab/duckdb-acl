# Spec 030: what goes with a dropped object

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

Five drop paths each kept a hand-written list of the tables to clean, and each had forgotten a
different one. Most visibly, a reference (spec 022) survived both of its ends: `DROP VIRTUAL TABLE
c.orders` left `c.by_customer` declaring a join path to an object that no longer existed. The lists
are now shared, and every path deletes through the same three pieces.

## Problem

What each path deleted, and what it missed:

| drop | missed |
| --- | --- |
| `DROP VIRTUAL TABLE\|VIEW` | references naming it, and their `reference_columns` |
| `DROP VIRTUAL [TABLE\|SCALAR] FUNCTION` | its grant rows (`role_object_caps`, `grant_columns`) and references naming it |
| `DROP VIRTUAL SCHEMA … CASCADE` | `object_columns`, `grant_columns` and `functions` under the path, and references naming anything under it |
| `DROP VIRTUAL CATALOG` | `references`, `reference_columns`, `grant_columns`, `role_schemas`, `schema_dropped` |
| `DROP ROLE` | `grant_columns` |

A dangling reference is not an enforcement hole — a reference grants nothing and is filtered at read
time by whether both ends are visible. It is a correctness one: `acl_references()` is what an agent
reads to learn the shape of the catalog, and it was answering with paths that no longer exist. The
`grant_columns` leftovers are the same shape one level down: rows describing the projection of a
grant that is gone.

`DROP VIRTUAL SCHEMA` also decided whether `CASCADE` was needed by counting only relations, so a
schema holding only a function dropped without a word — and left the function behind.

## Design

Three shared pieces, replacing five lists:

- **`ExactName` / `PrefixName`** build the name test for a column, so one call covers a single object
  (`"vname" = 'x'`) and a whole schema path alike.
- **`DropReferencesNaming`** removes every reference with either end matching, and the columns it
  recorded — the columns first, since they are found through the references they belong to. Nothing
  is ever refused on account of a reference: it grants nothing, so it must not stand in the way of a
  drop.
- **`DropGrantRowsFor`** removes `role_object_caps` and `grant_columns` for a name.

**A grant row cannot tell a relation from a function.** `role_object_caps` is keyed by
`(role, vcat, vname)` with no kind, so a relation and a function of the same name share one row.
Both drop paths therefore delete the grant rows only once nothing else answers to that name —
dropping table function `orders` beside relation `orders` leaves the relation's grant alone. The
relation path gained the same guard, which it did not have.

**A catalog's references belong to the catalog, not to a grant**, so they go whether or not `CASCADE`
was written — like the relations and functions beside them. `CASCADE` still governs only the rows
that belong to a *role* (`role_catalogs`, `role_object_caps`, `grant_columns`, `role_schemas`), which
is what the refusal message is about.

## Enforcement & security

- **Nothing became reachable.** Every change deletes rows; none creates or widens a grant.
- **Deleting a grant row early is the safe direction** — the object it named is gone, so the row could
  only ever grant access to a name that resolves to nothing.
- **The shared-name guard is the one place that deletes *less* than before** (the relation path). It
  keeps a grant on a function that still exists, which is what the administrator wrote; the previous
  behaviour silently revoked it.
- `DROP ROLE` and `DROP ISSUER` were already complete on the role side; `grant_columns` was simply
  newer than the list.

## Testing

`test/sql/acl_drop_cascade.test` (76 assertions): a reference removed with its `to` end, its `from`
end, and a `TO FUNCTION` end, with its columns; `grant_columns` going with `DROP ROLE` as well as with
the grant; a function's grant rows going with it, and surviving when a relation of the same name
remains; a schema cascade reaching references, `grant_columns`, `object_columns` and functions under
its path, and refusing without `CASCADE` when only a function is left inside; and a catalog drop
leaving no catalogs, relations, functions, references, reference columns, grant columns, schemas,
schema grants, object grants or tombstones — while the roles themselves stay, which are not the
catalog's to drop.

## Alternatives considered

- **Refuse to drop an object a reference names**, the way `DROP VIRTUAL SCHEMA` refuses when it still
  holds objects. Wrong for this kind of dependant: a reference is a hint that grants nothing, so
  making it an obstacle would trade a real operation for a decoration.
- **Foreign keys in the policy schema.** DuckDB supports them, and they would enforce this from the
  storage side — but the schema is created with `CREATE TABLE IF NOT EXISTS` and migrated with
  `ALTER TABLE ADD COLUMN`, so adding constraints to existing catalogs is a migration this spec does
  not need.
- **One `DropObjectRows` covering relations and functions together.** Too blunt: a relation drop would
  take a function of the same name with it.

## Follow-ups

- `role_object_caps` having no `kind` column is the reason for the shared-name guard. Adding one would
  let a grant name a table function and a relation separately, which is what the rest of the model
  already assumes (`CatalogRequireGrantTarget` treats a function's kind as part of its identity).
- `CatalogDropRelation` still reads before it writes and then writes twice (the deletions, then the
  tombstone), rather than doing the whole thing in one `WriteWithReads` transaction the way the other
  drop paths do. Pre-existing, and untouched here; it is the same read-then-write shape spec 027
  removed from the grant path.
- A view whose SQL selects from a dropped object is not detected — the SQL is opaque text, and
  `acl_refresh_schema` is what reports it as unbindable.
