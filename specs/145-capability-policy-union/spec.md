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
- **RETURNING is a read**: a DML target's `RETURNING` needs `select` on the object, and the `select` policy the same
  as the verb's (predicate, projection, visible columns, masks, field writes) - a principal whose update role is
  wider than its read role, or that holds no read at all, is refused with `RETURNING: …`, rather than returned rows
  or columns its reads cannot see (`TablePolicy::returning_refused`, set where the DML target is resolved).
- **Listings** (spec 035, what the read returns): the grant rows that narrow a listing's columns (`gcolumns`) are
  those holding `select`, and a role's probed projection (`grant_columns`) is listed only where that role reads the
  object; spec 144's alias levels follow when it lands.
- The memory store (dev mode) resolves a name to the first role holding it - no union, nothing lifted; unchanged.

## Enforcement & security

- Only narrows: a role contributes to a capability's policy only when it holds that capability, so no principal
  reads or writes more than before; a principal whose wider role lacked the capability reads less - what its grants
  say.
- RETURNING fails closed where the read and the write policy differ.

## Testing

- sqllogictest `acl_capability_union.test` (new, negative tests that fail on main): a read role with RLS and columns
  plus an `insert`-only role (catalog grant), plus a `CAPS '{}'` object grant, plus a live alias object - the read is
  the read role's; an `update` role with a predicate plus an `insert`-only role - the update stays confined, the
  insert is the insert role's; `UPDATE … RETURNING` refused where the policies differ, allowed where they agree; the
  listings agree with the reads.
- The existing multi-role tests (spec 011, 102's unions) unchanged.

## Alternatives considered

- **Dropping rows without `select` from one shared union**: a write-only principal's writes would lose their
  confinement (spec 024 reads the same policy).
- **Intersecting instead of uniting**: spec 011 is a union - a principal may do what any of its roles may.

## Follow-ups

- An unqualified name reads under the MAIN grants' roles only, a qualified one under every role holding the catalog
  (spec 144's review): a principal reads less through `t` than through `c.t` - narrower, not a leak.
