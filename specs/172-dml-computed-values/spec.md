# Spec 172: values an object computes on a write

- **Status**: implemented
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

## Design

The owner's decisions (2026-11-17): the client's value of a computed column is overwritten; a grant's mask is read,
the object's value written; the clauses are the object's only; ON UPDATE applies to every row an UPDATE touches - all of
it a rewrite of the statement, no trigger.

- **On the object.** `ON INSERT SET (…)` / `ON UPDATE SET (…)` on `CREATE VIRTUAL TABLE`, `ALTER VIRTUAL TABLE c.t SET
  ON INSERT (…) | SET ON UPDATE (…) | DROP ON INSERT | DROP ON UPDATE`; the function form `acl_add_relation(…, pk,
  on_insert, on_update)` (a shorter call keeps what is stored), `acl_alter_relation(c, t, 'on_insert' | 'on_update',
  items)`. Items `<column> = <expression>`, read by duckdb's parser as `UPDATE … SET <items>` (`ReadWriteValues`): no
  subquery, star, position, parameter, window, DEFAULT; a column set twice refuses.
- **What an expression reads.**
  - `new.<column>`: the value the client's write gives the column - its VALUES / SELECT / SET item, a computed column's
    own too (`email = lower(new.email)` normalizes it); never another item's result; on an INSERT that writes no such
    column, NULL; on an UPDATE that sets none, the row's current value.
  - a bare `<column>` on an UPDATE: the row's current value (`changes = changes + 1`); on an INSERT it refuses.
  - markers (`acl_claim`, `acl_has_role`): the writer's, baked where the statement is rewritten.
- **Judged where written** (`RequireWriteValues`): the object writable (the alias form - not a view, a computed list or
  an object RLS), each column and each `new.x` one of its columns, each expression binding over the object's row
  (`SELECT (<expr>) FROM (<the object's read>) AS "new"`, markers NULL); the author's function gate (spec 117,
  `BodyShape::SET_ITEMS`); no table to qualify or gate (no subquery). Any other ALTER re-judges the stored items.
- **The rewrite.**
  - INSERT: `SELECT <the client's columns but the computed>, <computed> FROM (<source>) AS __acl_written(<columns>)`
    (the injection path's shape); a drained quack stream (spec 042) by position, `SELECT * REPLACE (<computed> AS
    __acl_w<i>)` - a computed column the stream does not carry refuses. A listless INSERT takes the object's published
    order (`write_order`); an object with no list of its own needs named columns.
  - UPDATE and a MERGE's `WHEN MATCHED UPDATE`: each item replaces or is appended to the SET list; with another
    relation in scope (FROM, a MERGE's source) a bare column is the target's.
  - a MERGE's `WHEN NOT MATCHED INSERT`: as an INSERT's VALUES; `UPDATE SET *` refuses.
  - an upsert (`ON CONFLICT DO UPDATE`, `INSERT OR REPLACE`) refuses: a MERGE says which branch computes what.
  - after the grant's injections and before its write check (spec 024): the check sees the computed value.
- **Stored** in `relation_write_values(vcat, vname, verb, pos, column, expr)` (schema v28, `min_reader` 28 - an older
  build would write without computing them); a relation's drop, its undo (spec 154) and cascades take them; a
  principal's record never writes them.
- **Shown**: `information_schema.columns.column_default` = the ON INSERT expression; `platform.write_values`;
  `acl_check_catalog`'s `write_value_broken` (a value that no longer binds - every such write refuses) and
  `body_function_denied` for a stored one.

## Bulk ingest (checked first, the owner 2026-11-17)

How each load path meets the ON clauses, read from today's code:

| Path | What the node runs | ON INSERT |
|---|---|---|
| Flight `DoPutCommandStatementIngest`, append (spec 049) | ONE statement for the whole stream: `ACL INGEST '<h>' INSERT INTO t ("a", "b") SELECT "a", "b" FROM arrow_scan()`, rewritten like any INSERT | the named injection path (`ApplyInsertPolicy`): `SELECT <client's columns>, <computed> FROM (<arrow_scan>) AS __acl_insert(<names>)` - `new.x` is `__acl_insert.x`; a computed column the stream lacks is added |
| quack `SEND_DATA` drain (spec 042) | `INSERT INTO t SELECT * FROM scan_data_from_quack_client(…)`, positional, columns `col0…`; the list supplied from the object's (`write_order`, spec 171) | the stream path (`ApplyStreamInjections`): `SELECT * REPLACE (<computed> AS col<i>)` - `new.x` is the position of x; a computed column must be in the stream (else the positions shift - refused, as an injection is today) |
| Flight `temporary = true` (spec 050) | the session's temp table, no virtual object | none: applied when the client moves the rows with its own `INSERT … SELECT` |
| Flight `mode = create / replace` (spec 051) | `CREATE [OR REPLACE] TABLE … AS SELECT * FROM arrow_scan()` in a granted home | a new object has none; a replace keeps the object's, judged again over the new table (one that no longer binds refuses the replace) |

What follows for the design:

- **Cost**: one projection over the stream, vectorized; no row materialized; the load stays one statement, so
  duckdb's atomicity and the delivered-row cross-check (spec 049) hold. `now()` / `current_timestamp` is the
  statement's: every row of a load gets the same `created_at`.
- **Markers** (`acl_claim('tenant')`) are the session principal's, baked once per statement.
- **A computed column the client also sends.** A bulk loader sends the frame it has - often the object's whole
  listed shape, `tenant_id` and `created_at` included. Refusing it (question 1's option b) fails such a load on
  every batch; today's injection already drops the client's value on the named path and replaces it in place on
  the stream path. So for ingest the consistent answer is (a): the object's value wins, the client's is dropped,
  and the listing shows the computed expression as the column's `column_default`.
- **The write check** (spec 024) sees the computed value: a tenant RLS is satisfied by `tenant_id =
  acl_claim('tenant')` by construction, so a loader no longer sends the tenant at all.

## Found while building it

- **Flight ingest read a column at the wrong position** when the INSERT left one of the stream's columns unread (the
  computed `tenant`): the door's `ArrowScanFactory` ignores the projection `arrow_scan` pushes, and duckdb read the
  projected column at its position in the whole batch - the e2e saw a string's offsets as an INTEGER. The rewriter now
  reads the door's stream through `arrow_scan_dumb` (duckdb's scan without projection / filter pushdown, as for any
  producer that cannot project). Older than spec 172: a grant's injection over a middle column hit it too.

## Tests

- `test/sql/acl_dml_computed_values.test`: each verb, `new.`, markers, MERGE, the refused upsert, the grant's predicate
  satisfied by a computed tenant, refusals where written, ALTER / DROP ON, the listing's default, `platform.write_values`,
  the check's `write_value_broken`.
- `test/sql/integration/acl_quack_ingest.test`: a quack drain into a computing object, by position.
- `test/e2e/flight/adbc_client.py`: `adbc_ingest` into a computing object (the client's tenant overwritten), and the
  upsert flow - staged in the session, then `MERGE` (ON UPDATE on the matched row, ON INSERT on the new one).

## Alternatives considered

- **A grant's mask as the write value** (today): per role and tied to the read mask.
- **The source's own DEFAULT / generated columns**: physical, not every source has them (Parquet, DuckLake views), and
  they cannot read the writer's claims.
