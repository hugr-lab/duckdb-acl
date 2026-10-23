# Spec 145: a capability's policy is the union of the grants that hold it

- **Status**: implemented
- **Date**: 2026-10-23
- **Author**: hugr lab (found by spec 144's review; accepted by the owner 2026-10-23)

## Summary

A principal holding several roles reads (and writes) under the union of its roles' grant policies (spec 011). The
union takes every grant row on the object, whatever its capabilities: a role that may not read the object - an
ingest role with `insert` only, an object grant `CAPS '{}'` - counts as a role that reads it without restriction,
and lifts the other roles' row filter and column list. This spec makes each capability's policy the union of the
grant rows that hold that capability.

## Problem

Reproduced on main:

```sql
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN RLS (id = 2) COLUMNS (id);
ACL ADMIN GRANT CATALOG c TO ROLE auditor WITH (insert) MAIN;
ACL ROLE 'analyst' SELECT * FROM t;                 -- id = 2
ACL TOKEN '<roles: analyst, auditor>' SELECT * FROM t;   -- every row, every column
```

- **Reads**: the analyst's slice is lifted by a role that has no `select` at all - a data leak for any principal
  that holds a narrowed read role and a write-only one (an ingest role is the usual case). The same with an object
  grant `CAPS '{}'` on one role, and through a live schema alias.
- **Writes, the same shape**: an `update` confined by one role's predicate (spec 024) is lifted by another role that
  may only `insert`.
- `LookupRelation` / `LookupSchemaAlias` (src/acl_policy_catalog.cpp) add every row of the winning reading to the
  `GrantUnion`; the caps union is right, the policy union is not.

## Design

- **One rule**: the policy a statement runs under for a capability (`select` for a read, the verb for a DML target)
  is the union of the grant rows whose effective capabilities (the object grant's, else the schema's, else the
  catalog's - `EffectiveCaps`) hold it. The caps union stays over every row, as now: it decides *whether*; the
  capability's rows decide *what*.
- `PolicyStore::ResolveTable(principal, name, out, capability = "select")`; the cache key carries the capability;
  `ResolveDmlTarget` passes its verb (`insert`, `update`, `delete`, `merge`), every read keeps the default. A
  capability no row holds leaves the union empty - and the caps check refuses before the policy is used.
- **Upserts update** (found by the review, on main for one role too): `INSERT … ON CONFLICT DO UPDATE` and `INSERT OR
  REPLACE` change the row already there - they need `update` and run their SET under the update's policy
  (`ConflictUpdatePolicy`); an insert-only role updated through them, and an insert role beside an update role
  lifted its confinement. `OR REPLACE` has no SET to confine (duckdb writes every inserted column): refused under a
  row or column policy, with `ON CONFLICT … DO UPDATE SET …` named as what the policy confines. `ON CONFLICT DO UPDATE`
  under a column policy - the update's, or the read policy it reads under - is refused as an insert's already was
  (`ApplyInsertPolicy`): its SET and WHERE are never mapped column by column, so the re-review read a hidden column and
  wrote a hidden struct field through it.
- **A statement's own conditions read**: what UPDATE / DELETE / MERGE's SET, WHERE, ON and WHEN read of the target is
  judged under the read policy where every role the verb unites reads (the verb's slice then lies inside the read's;
  the verb's predicate stays AND-ed in), under the verb's otherwise - as a write-only role's always were (the
  re-review: under the read policy beside a non-reading verb role, a condition read a column on rows only the verb
  reaches, and the change count told its value).
- **RETURNING is a read** - where it returns a row already there (UPDATE, DELETE, MERGE, an upsert): it needs
  `select`, and every grant row the verb's policy unites must hold `select` too (`capability_rows_read`: the verb's
  policy is then no wider than the read's - fewer predicates OR-ed, fewer lists united), else it is refused with
  `RETURNING: …` (`TablePolicy::returning_refused`). A plain INSERT's RETURNING returns what the principal wrote and
  the defaults (a generated key): allowed as before, whatever it reads. A read that does not resolve refuses
  RETURNING alone, never the write.
- **Table and scalar functions**: a call is a read - `ResolveFunction` unites the rows holding `select` (the review:
  an insert-only role lifted a function grant's filter and columns).
- **Listings** (spec 035, what the read returns): the grant rows that narrow a listing's columns (`gcolumns`, the
  function keys' `gfcolumns`) are those holding `select` - for an object no row of the principal's may read (it only
  writes), every visible row's, as before (the review: a write-only role saw every column) - and a role's probed
  projection (`grant_columns`) is listed only where those rows include it; spec 144's alias levels follow when it
  lands.
- **The operator's screens** describe a role's own policy (`ResolveTableOwnPolicy`: under `select` when it holds it,
  else under the first verb it holds): `platform.effective_rights`, the lineage role tags (no `visible` / `masked`
  tag for a role that may not read), the runtime lineage of a write's target.
- **A view is a view by its form** (`TablePolicy::is_view`), never by a `query` - a grant's column list sets one on a
  table with no declared columns: DROP left the physical table behind and RENAME refused it (one role holding a
  column list and `drop`; with this spec, a multi-role principal whose wider role no longer lifts the list too).
- The memory store (dev mode) resolves a name to the first role holding it - no union, nothing lifted; unchanged.

## Enforcement & security

- A role contributes to a capability's policy only when it holds that capability: no principal reads, writes or
  upserts more than its grants for that capability say - a principal whose wider role lacked the capability now
  reads (writes) less. What a statement's conditions read is a read.
- RETURNING of a row already there fails closed where the verb's policy may be wider than the read's - a new refusal
  for a principal whose write role does not read (a plain INSERT's RETURNING is unchanged: it returns what was
  written, a generated key included). An upsert needs `update`, and `INSERT OR REPLACE` under a row or column policy
  is refused - both new refusals of what used to bypass the policy.

## Testing

- sqllogictest `acl_capability_union.test` (new, negative tests that fail on main): a read role with RLS and columns
  plus an `insert`-only role (catalog grant), plus a `CAPS '{}'` object grant, plus a live alias object - the read is
  the read role's; an `update` role with a predicate plus an `insert`-only role - the update stays confined, the
  insert is the insert role's; upserts (`ON CONFLICT DO UPDATE` confined by the update role, refused for an
  insert-only role, `INSERT OR REPLACE` refused under a row policy and allowed without one); `RETURNING` - a plain
  INSERT's allowed, an UPDATE's refused where a role the update unites may not read and allowed where all do; an
  update's condition read under the read policy; a write-only role's listing narrowed by its own lists; the
  operator's `effective_rights`; a table function under an insert-only second role.
- The existing multi-role tests (spec 011, 102's unions) unchanged.

## Alternatives considered

- **Dropping rows without `select` from one shared union**: a write-only principal's writes would lose their
  confinement (spec 024 reads the same policy).
- **Intersecting instead of uniting**: spec 011 is a union - a principal may do what any of its roles may.

## Follow-ups

- An unqualified name reads under the MAIN grants' roles only, a qualified one under every role holding the catalog
  (spec 144's review): a principal reads less through `t` than through `c.t` - narrower, not a leak.
- A catalog grant's row filter or column list makes every virtual scalar of the catalog refuse ("carries a policy"),
  for one role as before - with this spec a write-only second role no longer hides that.
- `ResolveTableOwnPolicy` describes a write-only role under the first verb it holds (insert, update, delete, merge):
  a role whose verbs carry different object grants is described by the first.
