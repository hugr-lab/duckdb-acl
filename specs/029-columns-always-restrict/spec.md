# Spec 029: a column list is a projection, whatever it is made of

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

An object's column list restricted the relation to what it named — unless every entry happened to be
a plain rename, in which case it silently restricted nothing and every unlisted column stayed
readable and writable. Every metadata surface but `DESCRIBE` reported the projection anyway. The
clause now means one thing at every level: **it names what the relation has.**

## Problem

Found while checking how DuckDB's column expressions (`COLUMNS(*)`, `* EXCLUDE`, `* REPLACE`, star in
`RETURNING`) behave under a principal. Those turned out to be sound — the stars expand over the
rewritten subquery, and every star form in `RETURNING` is already refused under a column policy. This
was underneath.

```sql
CREATE TABLE phys.main.t(id, tenant, amount, ssn);
ACL ADMIN CREATE VIRTUAL TABLE c.renamed AS phys.main.t COLUMNS (order_id = id, total = amount);
```

| asked | answered |
| --- | --- |
| `information_schema.columns` | `order_id, total` |
| `acl_relation_columns()` | `order_id, total` |
| `DESCRIBE renamed` | `order_id, tenant, total, ssn` |
| `SELECT * FROM renamed` | 4 columns, **`ssn = SECRET`** |
| `SELECT ssn FROM renamed` | readable |
| `INSERT INTO renamed (…, ssn)` | writable |

`IsRenameOnly` (`acl_admin_functions.cpp:74`) returns true when every entry renames one column onto
another, and such an object kept the alias form whose read is `SELECT * RENAME (…)` — which passes
every physical column through. The list was a *rename map*, not a projection.

Two things made this worse than a documented quirk:

- **The metadata disagreed with the data.** An administrator checking `information_schema` to confirm
  what a role sees was told two columns while the role read four. That is the shape of a leak that
  survives review.
- **The meaning flipped on the contents of the list.** Adding `ssn = NULL` — which reads as "also mask
  ssn" — turned the whole list from a rename map into a projection, so `tenant` silently disappeared
  too. Removing it silently re-exposed everything.

## Design

**One meaning.** A non-empty column list on an object is a projection: bare names, renames, masks and
computed columns alike. `COLUMNS (order_id = id, total = amount)` exposes two columns.

**Writability is untouched**, which is the thing section 2b of spec 010 exists to protect. The record
stays alias-form; what changes is the resolver, not the writer:

- the list populates `object_columns` (so the read projects `id AS order_id, amount AS total`) *and*
  `renames` (so a write still maps virtual → physical);
- `subquery_form` flips to true, exactly as a restricting *grant* already does — since spec 011 that
  is independent of `writable`, so DML still reaches the physical table;
- `write_columns` is seeded from the list, so an unlisted column is refused on the write path too.
  A projection that only covered reads would leave the other half of the hole open.

**A grant's list replaces the object's rather than adding to it.** `ApplyGrantPolicy` clears
`write_columns` before filling it from the grant, whose columns are already checked to be a subset.
Without that, an object allowing two columns and a grant allowing one would union to two.

**The stored schema is probed, so the types are real.** An alias-form projection now goes through the
same probe a subquery-form one does, so `information_schema` reports `INTEGER` rather than nothing.

**Fixing the resolver rather than the writer** means objects already stored as alias-form get the new
meaning without a migration.

## Enforcement & security

- **This closes a read path and a write path.** A deployment whose objects use rename-only lists will
  see columns disappear — that is the fix, not a regression: those columns were exposed against what
  every listing said. An administrator who wants a column exposed now names it (`tenant = tenant` is
  a valid entry).
- **The change only ever hides more.** No list gains a column.
- **A grant may only name what the object exposes**, which now bites for alias-form objects too — the
  same rule subquery-form objects always had. A grant's *expression* still runs over the physical row
  (spec 026), so a mask may compute from a column the object's projection dropped; both levels are
  written by the same administrator, so the object's projection was never a boundary against them.

## Testing

`test/sql/acl_columns_restrict.test` (58 assertions): the three shapes of a list all restricting
identically; the dropped column unreadable and unwritable; all three metadata surfaces agreeing with
the data path, with real types; the relation still alias-form, still writable, still mapping names
back; a physical column added later not joining the relation; an object with no list unaffected; a
grant refused for naming what the object does not expose while its expression still reads the
physical row; and a grant's list replacing the object's set of writable columns rather than adding to
it.

Updated for the new meaning: `acl_column_aliases.test` (spec 010's, which asserted the pass-through
directly), `acl_grant_policy.test` and `acl_grant_projection.test`.

## Alternatives considered

- **Keep the pass-through and fix only the metadata** — report four columns instead of two. Truthful,
  but it leaves `COLUMNS` meaning two different things depending on whether any entry happens to
  contain an expression, and leaves the flip-on-edit trap intact.
- **Keep both behaviours behind separate clauses** — `COLUMNS` restricts, a new `RENAME` clause passes
  through. A cleaner end state and still open: this spec does not preclude adding `RENAME` later, it
  just stops one clause meaning two things. Not done now because nothing has asked for pass-through
  renaming yet.
- **Refuse a rename-only list that does not cover every physical column.** It would surface the
  surprise instead of fixing it, and it needs the physical schema at write time — which spec 021
  established is not always available.

## Follow-ups

- "A grant lists a column the object does not expose" is refused at *resolution*, not where the grant
  is written. Specs 021 and 026 moved the predicate and the projection checks to the write path; this
  one has not moved yet, so an administrator learns about it from a role's failed read.
- A pass-through `RENAME (…)` clause, if a deployment turns out to want one.
