# Spec 038: a catalog-wide column list intersects, and a mask that cannot apply refuses

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

Spec 037 made an *object* grant hide and mask and nothing else. A *catalog* grant's column list
escaped that rule, because one list covers every object in the catalog and there is no single object
to check it against — so the same entry was applied on one object, invented on another and refused on
a third, with the metadata contradicting the read. This settles the semantics: a bare name **applies
where the object has it**, and a mask **refuses where it cannot be applied**. The column order a role
gets is the object's, for one role and for a union of them alike.

## Problem

Measured on the current build, `GRANT CATALOG c … COLUMNS (id, ssn = NULL)` against three objects of
one catalog:

| object | `SELECT *` | `duckdb_columns()` |
| --- | --- | --- |
| has `ssn`, plain alias | `id, ssn(NULL)` | `id, ssn` |
| no `ssn`, plain alias | `id, ssn(NULL)` — **invented** | `id` — **contradicts the read** |
| no `ssn`, declares its columns | refused | `id` |

Three behaviours, none of them chosen. And because the plain-alias case simply builds whatever the
list says, a catalog-level list can still rename, compute and reorder there — `label = upper(tenant)`
is accepted and appears — so spec 037's rule holds at the object level and is bypassed one level up.

Where the expression names a column the object lacks, the principal gets duckdb's own binder error
naming physical columns: the policy author's mistake, surfacing at a reader's query.

## Design

**A bare name intersects.** `COLUMNS (id, sku)` on an object that has no `sku` means the role sees
`id`. A catalog-wide list is a statement about a catalog, not about any one object in it, so a name
that does not apply simply does not apply — which is also what "a grant only narrows" already means
everywhere else.

**A mask refuses.** `ssn = NULL` on an object without `ssn` is an error. A mask is protection, and
protection that is silently skipped is the failure mode worth avoiding: an author who writes
`ssn = NULL` across a catalog must not end up with an object where `ssn` is readable because the
column happens to be spelled differently. Intersecting a mask away would be exactly that.

So the two halves of a list are not symmetric, on purpose: a bare name is permission (absent = no
permission to give), a mask is an obligation (absent = the obligation cannot be met).

**The order is the object's**, for a union of roles too — which finishes the follow-up spec 036 left
open. Each role's list is a subsequence of the object's columns (spec 037), so ordering the union by
the object's own order is well defined, and it is what a positional consumer needs.

**The mechanism needs no schema probe.** All three behaviours are what duckdb's own star expressions
do, so the generated read SQL can carry them:

```sql
SELECT COLUMNS(lambda c: lower(c) IN ('id', 'ssn'))
FROM (SELECT * REPLACE (NULL AS ssn) FROM phys.main.orders)
```

- the inner `REPLACE` applies the masks, and **errors when the column is not there** — the refusal;
- the outer `COLUMNS(lambda …)` keeps the listed names and **ignores the ones the object lacks** — the
  intersection;
- and both preserve the source's own column order — the object's order, for free.

For an object that declares its own column list the resolver already knows the columns and their
order, so it does the same three things in C++ and generates an explicit projection, as today.

**No schema probe at resolution, anywhere.** That is the constraint this design is built around: the
engine already answers "does this object have this column" while binding the statement we generate,
so asking it ourselves first would be a second query per resolution and a cache that goes stale
exactly when an alias is meant to be live.

**The same rule covers a table function's columns.** A grant on a table function today builds its
projection straight from the grant's list, with no check at all — so it can rename the function's
output and add columns to it, which is spec 037's problem one door along. A function's returns cannot
be known without calling it, so nothing can be validated where the grant is written; but its call is
already wrapped in a subquery on the read path, so the same star expressions apply unchanged: bare
names intersect, a mask that cannot be applied refuses, and the order is the function's own. Naming
and shaping a function's output stays where it belongs — the virtual catalog's declaration of it.

**The listing intersects the same way**, so `duckdb_columns()` and `SELECT *` stop contradicting each
other: the plain-alias branch filters the physical columns by the same names rather than adding the
grant's.

## Enforcement & security

- **Fail-closed where it counts.** The asymmetry is the safety property: an unapplied *mask* is an
  error, never a skipped protection. An unapplied *name* grants nothing, so ignoring it cannot widen
  access.
- **No privilege change.** An object-level grant still intersects a catalog-level one, so nothing a
  catalog list says can re-expose what an object grant took away.
- **A leak this closes**: today a catalog-level `label = upper(ssn)` on a plain alias puts `ssn`'s
  contents in the result under another name while `duckdb_columns()` reports the column does not
  exist. After this, that list is not expressible.
- **A leak this does not close, and must be recorded**: when a list matches *nothing* on an object,
  duckdb's star expression fails with a message that names the object's columns — `No matching columns
  found that match regex …  Did you mean: "id"`, or `Star expression "COLUMNS(list_filter(['id'], …))"
  resulted in an empty set of columns`. Both disclose column names to a principal who may see none of
  them. Mitigated by refusing at write time a catalog-level list that matches nothing on any object of
  the catalog (a list that fits nothing is a mistake, and that check *is* possible at write time);
  the residue is an object added later that matches nothing. See follow-ups.

## Testing

`test/sql/acl_catalog_columns.test` (new, 57 assertions):

- one catalog-wide `COLUMNS (id, ssn = NULL)` over three objects: applied where `ssn` exists,
  intersected to `id` where the object simply lacks it, refused where a *mask* cannot be applied;
- `duckdb_columns()`, `DESCRIBE` and the synthesized DDL agree with `SELECT *` on all three;
- a catalog-level entry naming something no object has is a mask that refuses and a bare name that
  intersects — the asymmetry, on one catalog;
- a grant on a table function may hide and mask its columns and may not rename or add to them;
- the union of two roles comes out in the object's order, not in either role's;
- an object grant still narrows a catalog grant, and cannot widen it.

The listing needed no change: for a plain alias it already filtered the physical columns by the
granted names, and the write-time probe never records a name that does not bind — so `SELECT *`,
`duckdb_columns()` and the synthesized DDL agree on all three objects without further work.

Full suite: 40 files, 3187 assertions, both C++ binaries.

## Alternatives considered

- **Refuse everything that does not fit.** Today's behaviour for objects that declare their columns.
  It makes a catalog-wide mask unusable — one object without the column breaks the whole catalog for
  that role — and punishes an object for the breadth of a policy that is not about it.
- **Intersect masks too.** Symmetric and unsafe: a mask that quietly does not apply is a column the
  author believes is protected and which is not.
- **Probe the object's schema at resolution.** Ruled out: it is a second query per resolution, and the
  cache it would need goes stale exactly when an alias is supposed to be live. The star expressions do
  the same work inside the statement we already generate. Its only advantage — our own error text —
  is worth less than a probe on every read.

## Follow-ups

- **The empty-intersection message is duckdb's, and it names columns.** The write-time check catches
  the common case; a sentinel column that keeps the set non-empty would let us produce our own
  refusal instead, at the cost of a wrapper in every generated projection.
- **A mask's refusal is also duckdb's message** (`Column "ssn" in REPLACE list not found in FROM
  clause`) rather than ours, and it arrives at the reader rather than at the author. It says the right
  thing, but it does not say which grant caused it.
- Column names containing quoting metacharacters: the generated lambda quotes them as string literals
  and the `REPLACE` alias as an identifier, both escaped. Two neighbouring places did not, and the
  self-review found them:
  - the write-time probe built `<source> AS <alias>` unquoted, so a column named `od''d` made the
    probe itself unparseable and such a column could never be granted at all. Fixed here.
  - the SQL grammar keeps an identifier's quotes in the list it stores, so `COLUMNS (id, "od''d")`
    records the name *with* its quotes and then matches nothing. The function form
    (`acl_grant_object(…, 'id, od''d')`) works. Unquoting per item in the grammar is its own change,
    with its own question about what `"a b"` should mean.

  Names are compared case-insensitively, as duckdb identifiers are.
- **An object whose mask cannot be applied is unreadable but still listed**, showing the columns the
  bare names intersect to. Same shape as spec 037's follow-up about conflicting roles: the listing
  describes something no query can return. Both want the same fix — a listing that asks whether the
  object resolves at all.
