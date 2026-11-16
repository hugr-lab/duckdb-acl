# Spec 172: values an object computes on a write

- **Status**: draft (design for the owner)
- **Date**: 2026-11-17
- **Author**: duckdb-acl

## Summary

A virtual table states what a write sets by itself - the tenant from the writer's claim, a timestamp, a value derived
from what the client writes - so no client supplies or forges them:

```sql
CREATE VIRTUAL TABLE c.orders AS pg.public.orders COLUMNS (id, amount, discount_rate, discount, tenant_id, created_at)
  ON INSERT SET (tenant_id = acl_claim('tenant'), created_at = now(), discount = new.amount * new.discount_rate)
  ON UPDATE SET (updated_at = now(), discount = new.amount * new.discount_rate);
ALTER VIRTUAL TABLE c.orders SET ON UPDATE (…) | DROP ON INSERT | DROP ON UPDATE;
```

## Problem

Today the only way is a grant's mask: a masked column is assigned its mask on a write (spec 024's injection), so
`MASK (tenant_id AS acl_claim('tenant'))` fills the tenant - and also replaces it on every read, per role. A value the
object computes on a write is the object's, like its columns (spec 158), not a role's read mask.

## Design (proposed)

- **On the object.** `ON INSERT SET (…)` / `ON UPDATE SET (…)`: items `<column> = <expression>`, each column one of the
  object's, each expression one expression (spec 148) judged by the author's function gate (spec 117), its tables
  qualified (spec 160) and inside the author's sources (spec 138). Read by duckdb's parser.
- **What an expression reads.**
  - `new.<column>`: the value this write gives the column - the client's (its VALUES / SELECT / SET), or the one another
    item computes, else on an UPDATE the row's current value, on an INSERT the column's default.
  - a bare `<column>` on an UPDATE: the row's current value (as in duckdb's SET); on an INSERT, `new.` is required.
  - markers (`acl_claim`, `acl_has_role`): the writer's, baked where the statement is rewritten.
- **Where it applies.** Every write the ACL decides: INSERT (VALUES and SELECT), UPDATE, MERGE (`WHEN MATCHED UPDATE`
  = ON UPDATE, `WHEN NOT MATCHED INSERT` = ON INSERT), an upsert's `DO UPDATE` (ON UPDATE), Flight ingest and quack
  SEND_DATA (an INSERT). Never under `ACL NATIVE` (break-glass) nor a physical write of the operator.
- **Rewrite.** INSERT: the client's source wrapped as `SELECT <client's columns>, <computed> FROM (<source>)` - the
  injection path spec 011 / 024 already has; UPDATE: `SET <column> = <expression>` with each `new.x` replaced by the
  client's SET expression for `x` (else `x`).
- **With the grant's checks.** A computed value is checked against the grant's predicate like any written value (spec
  024): `tenant_id = acl_claim('tenant')` satisfies a tenant RLS by construction, so the client no longer has to send
  it. RETURNING shows the computed value where the role may read the column.
- **Stored** in a new table `relation_write_values(vcat, vname, verb, pos, column, expr)` (schema v28).
- **Listings**: `information_schema.columns.column_default` shows the ON INSERT expression (a hint for tools); a
  `platform` view lists both.
- **Writable objects only**: an object whose list computes a column is read-only, and so are its ON clauses' targets'.

## Open questions (the owner's)

1. **The client's own value for a computed column**: (a) overridden silently (as an injection is today), (b) refused
   ("<column> is computed on INSERT"), or (c) used when given - ON INSERT as a default only. Proposed: (b) for ON
   INSERT and ON UPDATE alike - a silent override hides a client bug; a default is duckdb's own DEFAULT.
2. **A grant's mask on a computed column** (the injection also assigns it): refuse writing such a grant, or let the
   object's value win on writes and the mask on reads. Proposed: the object's value on writes, the mask on reads.
3. **Per role**: ON clauses on the object only (proposed), or also on an object grant (`GRANT … ON INSERT SET …`), as
   a role-specific stamp.
4. **ON UPDATE of a column the client does not touch** (`updated_at = now()`): always applied to every updated row
   (proposed), or only when some listed column changes.

## Tests

`test/sql/acl_dml_computed_values.test`: each verb, `new.`, markers, MERGE / upsert / ingest, the grant's predicate
satisfied by a computed tenant, RETURNING, refusals where written.

## Alternatives considered

- **A grant's mask as the write value** (today): per role and tied to the read mask.
- **The source's own DEFAULT / generated columns**: physical, not every source has them (Parquet, DuckLake views), and
  they cannot read the writer's claims.
