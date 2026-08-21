# Spec 037: a grant gives access, the catalog gives shape

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

A grant's column list could do four different things: hide columns, mask them, **rename** them, **add**
computed ones, and **reorder** them. Only the first two are a grant's business. Naming, ordering and
computing belong to the virtual catalog, which is where an object's shape is defined. From here a
grant's column list may only name columns the object already exposes, optionally masking one, and its
written order carries no meaning — the object's order is the order.

## Problem

Two layers were doing the same job with different words. The catalog defines an object's shape:

```sql
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders COLUMNS (id, tenant, ssn = NULL);
```

and a grant could redefine it:

```sql
ACL ADMIN GRANT OBJECT c.orders TO ROLE analyst COLUMNS (note, initial = tenant[1], id);
```

That grant renames (`initial` is not a column), computes (`tenant[1]`), and reorders (`note` first).
The result is that "what shape does this object have?" has no single answer — it depends on who is
asking, which is exactly the property that made spec 036 necessary and that keeps making metadata
awkward:

- **the order becomes per-principal**, so a column's position depends on the roles asking; spec 036
  had to pin an arbitrary-but-deterministic rule because the object's own order had been discarded;
- **a computed column exists for one role and not another**, so `duckdb_columns()` describes different
  objects for different callers and the ordinal cannot be a property of the object (which is the
  natural thing for it to be);
- **the same masking can be expressed twice**, at either level, with different consequences.

And the enforcement is uneven. `ApplyGrantPolicy` already refuses a grant column the object does not
expose — but only when the object declares a column list. For a plain alias, `known` is true
unconditionally, so a grant over `phys.main.orders` may name anything at all, including a column that
does not exist (which then fails at query time, for the principal, rather than at write time, for the
author).

Measured: of the eight grant-level column lists in the test suite, **all eight** rename or add. Not
one masks an existing column, which is the thing a grant is actually for.

## Design

**The rule.** A grant's column list is a subset of what the object exposes, where an entry is either

- `name` — the column, as the object exposes it, or
- `name = <expr>` — the same column with its value replaced (a mask),

and `name` must be a column the object exposes. Nothing else is a grant's business.

**Rejected at write time, by name.** The machinery is already there: `GrantProjectionStatements`
probes the grant's projection against the object (spec 026), and `ProjectionSchema` already runs
`SELECT * FROM <source> WHERE false` to check the object binds. That probe's own column list is the
answer to "what does the object expose" for a plain alias; for an object with a declared list it is
`relation_columns`. A grant naming anything else is refused where it is written:

```text
acl: the grant on "orders" lists "initial", which the object does not have - a grant may hide or
mask a column, but naming, computing and ordering belong to the virtual catalog (spec 037)
```

Refusing rather than ignoring is the point: a policy author who writes a mask that is silently
dropped believes a column is protected when it is not.

**The written order carries no meaning.** The stored column list is normalised into the object's own
order when the grant is written, so a single role always reads columns in the object's order,
whatever order the author typed. That makes the ordinal a property of the object rather than of the
grant — which is what spec 036 wanted and could not have while grants could reorder.

**The read path keeps its check.** `ApplyGrantPolicy`'s existing refusal stays as a fail-safe for
grants that did not come through our writer — a policy written directly into the catalog tables, or
served by the function driver, which we do not normalise.

## Enforcement & security

- **Strictly narrowing.** Every capability removed here was a way for a grant to *add* something — a
  name, a value, a position. A grant can still hide and still mask, which is all it needs to narrow.
  Nothing a grant could deny before becomes permitted.
- **Fail-closed at the door it belongs to.** An impossible grant now fails for its author at write
  time instead of for a principal at query time, and the message says which layer owns the thing they
  were trying to do.
- **The function driver is not normalised**, because we do not write its rows; a driver that serves a
  reordering list gets that order. The read-path check still refuses a column the object does not
  expose, so the security property holds; only the ordering guarantee is ours to make.

## Testing

`test/sql/acl_grant_scope.test` (new, 38 assertions):

- a grant that masks an existing column (`ssn = NULL`) — the case the suite never covered — works, and
  the mask applies on read;
- a grant naming a column the object does not have is refused at write time, both for an object with
  a declared column list and for a plain alias (the case that used to slip through);
- a grant computing a new column (`initial = tenant[1]`) is refused with the same message;
- a grant listing columns out of order reads them in the object's order, and the listing and DDL agree
  with it;
- the object keeps its own powers: renaming, computing and ordering through
  `CREATE VIRTUAL TABLE … COLUMNS (…)` are unaffected.

- what the operator sees stored is the normalised list (`acl_object_grants()` returns
  `id, amount, ssn = NULL` for a grant typed `ssn = NULL, amount, id`).

Five existing files moved their grant-level renames into the object definitions, which is where they
belong. Two of them changed what they assert, both correctly:

- `acl_columns_restrict.test` carried a comment saying the refusal happened "at resolution rather than
  where the grant is written (see the spec's follow-up)" — that follow-up is this spec, and the
  assertion is now a write-time refusal;
- `acl_grant_policy.test` likewise refused `COLUMNS 'id,ssn'` on the principal's read; it refuses on
  the grant now.

`acl_grant_projection.test` (spec 026) kept both of its cases and gained one: an expression that does
not bind is still refused as before, and a *name* the object does not have is refused before its
expression is tried.

Full suite: 39 files, 3130 assertions, both C++ binaries.

## Alternatives considered

- **Accept and ignore the extra names.** The failure mode is a policy author believing a column is
  masked when it is not — the worst kind of quiet.
- **Keep renaming in grants and drop it from the catalog.** Backwards: the catalog is the shared
  definition; a per-role name means every consumer of the metadata sees a different object.
- **Normalise at read time instead of write time.** Cheaper to implement and wrong in the same way as
  ignoring: the stored policy would keep saying something we do not honour.

## Follow-ups

- **A catalog-level grant's column list escapes this rule entirely**, and measuring it showed the
  situation is worse than "not validated". One list applies to every object in the catalog, so there
  is no single object to check it against at write time — and at read time the same entry behaves
  three different ways. For `COLUMNS (id, ssn = NULL)` granted on a catalog:

  | object | `SELECT *` | `duckdb_columns()` |
  | --- | --- | --- |
  | has `ssn`, plain alias | `id, ssn(NULL)` | `id, ssn` |
  | no `ssn`, plain alias | `id, ssn(NULL)` — **invented** | `id` — **contradicts the read** |
  | no `ssn`, declares its columns | refused | `id` |

  So a catalog-level list can still rename, compute and reorder on plain aliases (`label =
  upper(tenant)` is accepted and appears), the metadata does not see what it adds, and where the
  expression references a column the object lacks the principal gets duckdb's raw binder error naming
  physical columns. No privilege is escalated — an object-level grant still intersects it away — but
  the model is violated and the listing lies, which is exactly what specs 035-037 have been closing.
  Deciding the semantics (intersect per object, or refuse) is its own spec; intersecting is the one
  consistent with "a grant only narrows", and it needs the read path to know a plain alias's columns.
- **The union of several roles is still ordered by spec 036's rule** (first role naming the column,
  roles in name order), not strictly by the object's order. Each role's list is now a subsequence of
  the object's order, so an order-preserving merge would give exactly the object's order for the union
  too; that is a small algorithm and its own change.
- Spec 026's write-time probe stored "a computed column the object never had" — that half of it now
  cannot arise from a grant. The probe still earns its keep for masks that change a column's type.
- Spec 036's role-name ordering rule becomes almost vacuous once the follow-up above lands; the spec
  stays as the record of why determinism matters here (a quack client projects positionally).
