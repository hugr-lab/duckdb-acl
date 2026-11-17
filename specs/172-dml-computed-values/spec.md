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

## Bulk ingest (checked first, the owner 2026-11-17)

How each load path meets the ON clauses, read from today's code:

| Path | What the node runs | ON INSERT |
|---|---|---|
| Flight `DoPutCommandStatementIngest`, append (spec 049) | ONE statement for the whole stream: `ACL INGEST '<h>' INSERT INTO t ("a", "b") SELECT "a", "b" FROM arrow_scan()`, rewritten like any INSERT | the named injection path (`ApplyInsertPolicy`): `SELECT <client's columns>, <computed> FROM (<arrow_scan>) AS __acl_insert(<names>)` - `new.x` is `__acl_insert.x`; a computed column the stream lacks is added |
| quack `SEND_DATA` drain (spec 042) | `INSERT INTO t SELECT * FROM scan_data_from_quack_client(…)`, positional, columns `col0…`; the list supplied from the object's (`write_order`, spec 171) | the stream path (`ApplyStreamInjections`): `SELECT * REPLACE (<computed> AS col<i>)` - `new.x` is the position of x; a computed column must be in the stream (else the positions shift - refused, as an injection is today) |
| Flight `temporary = true` (spec 050) | the session's temp table, no virtual object | none: applied when the client moves the rows with its own `INSERT … SELECT` |
| Flight `mode = create / replace` (spec 051) | `CREATE [OR REPLACE] TABLE … AS SELECT * FROM arrow_scan()` in a granted home | a new object has none; a replace of an object that carries ON clauses is refused - they are the operator's declarations |

What follows for the design:

- **Cost**: one projection over the stream, vectorized; no row materialized; the load stays one statement, so
  duckdb's atomicity and the delivered-row cross-check (spec 049) hold. `now()` / `current_timestamp` is the
  statement's: every row of a load gets the same `created_at`.
- **Markers** (`acl_claim('tenant')`) are the session principal's, baked once per statement.
- **A computed column the client also sends.** A bulk loader sends the frame it has - often the object's whole
  listed shape, `tenant_id` and `created_at` included. Refusing it (question 1's option b) fails such a load on
  every batch; today's injection already drops the client's value on the named path and replaces it in place on
  the stream path. So for ingest the consistent answer is (a): the object's value wins, the client's is dropped,
  and the listing says the column is computed (`column_default` / `is_generated`).
- **The write check** (spec 024) sees the computed value: a tenant RLS is satisfied by `tenant_id =
  acl_claim('tenant')` by construction, so a loader no longer sends the tenant at all.

## Open questions (the owner's)

1. **The client's own value for a computed column**: (a) overridden (as an injection is today), (b) refused
   ("<column> is computed on INSERT"), or (c) used when given - ON INSERT as a default only. Proposed after the
   ingest check: (a) - bulk loaders send the whole frame, and an injection already overrides on both ingest paths;
   the listing marks the column computed. (b) was proposed before it.
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
