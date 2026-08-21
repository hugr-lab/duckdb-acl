# Spec 018: a role may create a view — `CREATE VIEW` through the ACL

- **Status**: implemented
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

Spec 016 let a role create and drop tables and refused views. A view is now allowed, and it is an
**object of the virtual catalog in its own right**: its body is resolved once, with its author's
rights, and reading it is decided by the grant on the view — not by grants on what it happens to
read. Claims stay markers, so the same view still shows each reader their own rows.

## Design

### The body is resolved with the author's rights

```sql
ACL ROLE "wide" CREATE VIEW vs.report AS SELECT id, amount FROM vs.orders;
```

is stored as a virtual view whose SQL is what `wide`'s policy resolves that query to — the physical
target, `wide`'s projection, `wide`'s predicate — with `acl_claim('tenant')` left standing:

```sql
SELECT id, amount FROM (SELECT id, amount, region FROM phys.lake.orders
                        WHERE tenant = acl_claim('tenant')) AS orders
```

Nothing physical is created; the record is the whole of it. This is the same kind of object an admin
creates with `CREATE VIRTUAL VIEW` — the only difference is whose rights resolved the body.

**Claims are deliberately not baked.** The author's *policy* is frozen (that is what a view is), but
the tenant is not: a reader in another tenant sees their own rows, not the author's. Baking would
nail the view to whoever happened to create it.

### It describes its columns like any other object

The write-time probe of spec 010 binds a body with the markers nulled, so `information_schema.columns`
answers for these views too. That probe used to null markers only in the top-level `SELECT`, which is
never where a resolved body keeps them — the author's policy lands in a `FROM` subquery. It now walks
the whole node (subqueries, CTEs, set operations, scalar subqueries), which also fixes admin-authored
templates whose marker sits below the top level.

### Reading it

A view is granted like any other object, and that grant is the whole decision. A reader needs no
rights on what the view reads — that is the point of a view, and it is how the admin-authored ones
have always worked (spec 006).

### Capabilities and lifecycle

The table rules of spec 016: `create` on the schema to make one, `drop` to remove it. `INTO` and
`VIRTUAL ONLY` have nothing to say, since nothing physical is created. `DROP VIEW` removes the record.

## Enforcement & security

A view carries its author's reach, so **`create` on a schema is a strong grant**: it is the power to
publish anything the holder can read, to everyone who can read that schema — because a schema grant
(spec 015) covers objects that appear in it later, including this one. No administrator is involved
in that chain.

That is a deliberate choice, made because a view is meant to expose a controlled slice without
granting the source. Two things bound it: the author can only expose what they can already read, and
an operator who does not want that power in a schema simply does not grant `create` there.

If a deployment wants the narrower rule, the lever is the grant chain rather than the view: give
`create` only where publishing is intended, and grant views explicitly rather than through a schema
grant.

## Testing

`test/sql/acl_create_view.test` (63 assertions): a role with `create` making a view and reading it;
a body that names a physical object refused, so `create` publishes only what its holder can read;
the same refusal through a `UNION` branch, and a legitimate `UNION` body carrying the author's
predicate in *both* branches; `information_schema.columns` describing a view whose body carries a
claim, and one whose body is a set operation;
the stored body being the resolved query with the claim still a marker and nothing physical created;
a role whose own grant hides a column reading it through the view (the author's rights shaped the
body) while still being refused that column on the table; each reader's own tenant through the same
view; a reader with no grant on the view refused and, once granted, reading it without any right on
the source; `create` required to make one and `drop` to remove it; a view over a view; and an
admin-authored virtual view behaving identically, since it is the same kind of object.

A view body may be any query node, so the branch-by-branch walk it relies on got its own coverage
while it was under review: `test/sql/acl_set_operations.test` (42 assertions) checks that each branch
of a `UNION`/`EXCEPT`/`INTERSECT` keeps its own policy, that no branch — including a recursive CTE's
anchor, one inside a scalar subquery, and one feeding an `INSERT` — is a way around a grant, and that
a refused statement writes nothing. That behaviour predates this spec; only the tests are new.

## Alternatives considered

- **Resolve the body per reader** (the first cut of this spec): every reader's own policy would apply
  inside the view, so a view could never expose a controlled slice — it would be a saved query and
  nothing more. Rejected: that is a macro, not a view, and it makes views useless for the case they
  exist for.
- **Bake the claims too**: freezes the view to its author's tenant, which turns every multi-tenant
  view into one view per tenant.
- **Keep refusing**: a role that may create tables but not views is an odd line, and the workaround
  (materialise a table) is worse in every way.

## Follow-ups

- `CREATE OR REPLACE` on a view another view was built over: the older body is already inlined in the
  newer one, so replacing the source does not change what was built on it. Worth stating in the docs,
  and possibly worth recording the dependency.
