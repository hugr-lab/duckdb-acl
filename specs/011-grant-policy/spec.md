# Spec 011: per-grant policy — one object, different slices per role

- **Status**: implemented (catalog and object levels; the schema level follows `GRANT SCHEMA`)
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

Policy stops being a property of the object alone. A grant of a catalog or an object to a role carries
**its own** capabilities, RLS predicate and column list; the object definition remains the base, and a
grant may only **narrow** what is read — while on the write path it **supplies values**, so a narrowed
grant stays writable. This is what makes one virtual object serve several roles (analyst sees their
tenant, auditor sees everything, compliance sees a different slice) without duplicating the object per
role.

## Problem

Before this, RLS and masks lived on the object (spec 006), identical for everyone holding the catalog.
The multi-tenant case worked — the predicate is the same and only the claim value differs — but any
role that needed a *different shape* of policy forced a second copy of the object in a second catalog,
and with it a second schema, comment and probe to keep in sync. There was also no way to say "this
role may write, and every row it writes belongs to it": a write-capable grant wrote anything.

## Design

### Where policy lives

```sql
ACL ADMIN GRANT CATALOG sales TO ROLE analyst CAPS '{"select": true}' MAIN
      RLS 'tenant = acl_claim(''tenant'')';
ACL ADMIN GRANT TABLE sales.orders TO ROLE analyst
      CAPS '{"select": true, "insert": true, "update": true, "delete": true}'
      RLS 'tenant = acl_claim(''tenant'')'
      COLUMNS 'id,amount,tenant=acl_claim(''tenant'')';
ACL ADMIN ALTER GRANT CATALOG sales TO ROLE analyst SET RLS '…' | SET COLUMNS '…';
```

`CAPS` / `RLS` / `COLUMNS` (and `MAIN` on a catalog grant) may be written in any order; the same
clauses are reachable as `acl_grant_catalog(role, vcat, caps, is_main, rls, columns)` and
`acl_grant_object(role, vcat, vname, caps, rls, columns)`. The object form takes any name of the
catalog — a relation, a schema alias or a **virtual table function**.

- **capabilities**: the most specific level that names the role wins (object → catalog), then union
  across the principal's roles, as everywhere else;
- **policy (RLS + columns)**: *composes down the chain* rather than overriding — predicates are
  `AND`-ed (catalog → object → the object definition's own RLS), column lists intersect. Across the
  principal's roles the effective policy is the **union** (predicates `OR`-ed, columns unioned, a
  column one role sees unmasked is unmasked), matching how capabilities already union — so a role
  *without* a narrowing grant lifts the narrowing for a principal that holds both;
- a column hidden by the object definition can never be re-exposed by a grant: naming it is an error,
  not a silent widening. A grant can only hide more or mask harder.

### The read shape

A narrowed relation reads through the usual subquery: the grant's columns become the projection
(mapped through the object's renames, so `COLUMNS 'order_id'` reads `id AS order_id`), and the
composed predicate becomes the `WHERE`. A grant that only narrows rows keeps every column
(`SELECT *`, or `SELECT * RENAME (…)` when the object renames some). A **view**'s SQL is wrapped
instead, so the grant applies to the view's output rather than to its source.

### Table functions

A virtual table function is a read of rows like any relation, so a grant narrows its **result**: the
expanded macro (or the retargeted physical call, for the `alias` form) is wrapped in
`SELECT <columns> FROM (<the call>) [WHERE <predicate>]`. The call's own arguments still reach the
macro through `acl_arg(n)` — the policy is applied around the call, not inside it, so the two never
mix. A **scalar** function has neither rows nor columns, so a policy on one is refused at grant time
rather than silently ignored.

### The write path: grants supply values

A grant column with a **value expression** (built from claims/constants, e.g.
`tenant=acl_claim('tenant')`) is not a mask but an assignment:

- `INSERT`: the value is **added when absent and overridden when the user supplied it** — the source
  is projected through `SELECT <passthrough…>, <injected…> FROM (<the user's source>)`, so `VALUES`
  and `INSERT … SELECT` behave the same, and the row belongs to the principal by construction (no
  separate `WITH CHECK` machinery);
- `UPDATE`: the same override on `SET`, so a row cannot be moved to another tenant, and the grant's
  predicate is **`AND`-ed into the statement's `WHERE`**, so only rows the role can see are touched;
- `DELETE`: the predicate is `AND`-ed into `WHERE` likewise;
- a column whose expression depends on the row (`total = amount * 2`) is **not writable**: the value
  is baked and checked at rewrite time, and a column reference in it makes the write an error.

So a narrowed grant is writable, and "row-level security on writes" falls out of value injection plus
predicate `AND`-ing rather than being a separate feature.

### Fail-closed rules

- a column list makes an `INSERT` **name its columns**: without a list we do not know which physical
  columns are written, so there is nothing to check the grant against (`DEFAULT VALUES`, `INSERT BY
  NAME` and `ON CONFLICT` are refused for the same reason);
- `RETURNING` reads the physical table, so under a column policy it may only name columns the grant
  exposes as-is — a masked/injected column and `RETURNING *` are refused, otherwise RETURNING would
  be a way back to what the grant hid;
- a narrowed relation is refused in DML with a **second relation in scope** (`UPDATE … FROM`,
  `DELETE … USING`, `MERGE`): an unqualified reference — the user's, or the one the policy adds to
  the `WHERE` — could belong to either side, and guessing would silently write the wrong column;
- a catalog-level predicate that references a column a table does not have makes that table
  **inaccessible** for the role (a bind error), rather than silently not filtering;
- `GRANT CATALOG`/`GRANT TABLE` are privilege administration (spec 009): they need an unrestricted
  manage scope, so a catalog-scoped manage cannot widen or narrow other roles' grants;
- a grant naming an object that does not exist is refused at grant time — a policy that never applies
  is worse than no policy — and so is `RLS`/`COLUMNS` on a scalar function.

### Storage

`acl.role_catalogs` and `acl.role_object_caps` each gain `rls` and `columns` (schema v3, migrated with
`ALTER TABLE … ADD COLUMN IF NOT EXISTS`, so an existing catalog upgrades in place). Resolution loads
the whole chain for the principal's roles in the same JOIN-shaped query that already fetches grants
(spec 006), so a miss still costs one round trip. The **function-driver** contract has no policy
columns — a platform expresses policy in its own callbacks — so driver mode composes to "no
grant-level narrowing".

## Enforcement & security

Narrowing-only composition means a grant cannot become an escalation path; value injection means a
write-capable role cannot forge rows outside its slice; predicate `AND`-ing means it cannot update or
delete outside it either; the `RETURNING` and second-relation rules keep the write path from becoming
a read path. All of it is decided at parse time in the rewriter, so a refusal happens before any
statement of the batch executes.

## Testing

`test/sql/acl_grant_policy.test` (88 assertions): one object granted to three roles with three slices
(tenant RLS + column list, unrestricted, catalog-level predicate); the injected column reading back as
its value; a hidden column gone; union across the two roles of one JWT principal lifting the
narrowing; `INSERT` injecting and overriding a claim value through both `VALUES` and `SELECT`; an
ungranted column and an unqualified `INSERT` refused; `UPDATE`/`DELETE` bounded by the `AND`-ed
predicate and unable to move a row out of the slice; `RETURNING` of a hidden, masked or starred column
refused while a granted one reads back; `UPDATE … FROM` and `MERGE` refused; a view staying read-only
under a grant; renames composing with a grant; a grant re-exposing a hidden column refused and one
masking harder accepted; a grant on an unknown object refused; a row-derived column refused on write;
`ALTER GRANT … SET RLS` taking effect on the next query; a table function narrowed by a grant in both
the macro and the `alias` form (with `acl_arg` still carrying the call's argument) while a policy on a
scalar function is refused; and a catalog-scoped manage refused when handing out a slice.

## Alternatives considered

- **Policy only on the object** (before this): forces a copy of the object per role shape.
- **Policy only on the grant**: forces repeating the tenant predicate in every grant, and loses the
  place where an object says what it fundamentally is.
- **Grants that may widen** (override rather than narrow): makes every grant a potential escalation
  and destroys the ability to reason about an object's worst case.
- **A separate `WITH CHECK` clause** for writes: a second thing to keep in sync with the read policy;
  value injection gives the same guarantee from the column list that is already there.

## Follow-ups

- **A predicate alone does not confine an `INSERT`**: rows the role could not read back can still be
  written unless the grant names a value column (there is no `WITH CHECK` evaluation of the predicate
  against the inserted values). Either evaluate the predicate on the written row, or refuse `insert`
  on a grant whose predicate no value column covers.
- A virtual **table function** is still gated only by the existence of the catalog grant: the `select`
  capability of spec 003 gates relations, not function calls. The grant chain now reaches functions,
  so the capability check belongs there too.
- **Schema level**: `GRANT SCHEMA sales.raw TO ROLE r …` needs a schema-grant row; the composition
  already takes an arbitrary chain, so it is storage plus grammar.
- `MERGE`, `UPDATE … FROM` and `DELETE … USING` on a narrowed relation: they need every reference to
  the target qualified before the policy predicate can be added safely.
- Column lists split on `,`, so an expression may not contain a top-level comma — the unified DDL
  syntax (design 004) parses them properly.
- `create`/`drop` capabilities and the DDL path build on the same grant chain.
- Introspection (spec 010 part 3) must show the **effective** columns of the principal, not the
  object's own list.
