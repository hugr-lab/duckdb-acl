# Spec 012: the `select` capability gates virtual function calls

- **Status**: implemented
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

Spec 003 made `select` gate every read of a relation. A **virtual function call is a read too** — a
table function returns rows, and a scalar function's template is admin-authored SQL that may read a
physical table directly — but both are let through on the mere existence of a catalog grant. This
spec closes that: the capability decides, and spec 011's per-object grant is the escape hatch for
"this role may call *this* function without holding read on the catalog".

## Problem

`ResolveFunction` never fetched capabilities, and `RewriteTableFunction` never checked any:

```sql
ACL ADMIN GRANT CATALOG sales TO ROLE ingest CAPS '{"insert": true}' MAIN;   -- write-only
ACL ROLE "ingest" SELECT * FROM report(0);      -- passes today, reads rows
ACL ROLE "ingest" SELECT tenant_of(1);          -- passes today, may read a table in its template
```

A write-only grant (an audit or ingest table) is exactly the case where the extension must not leak
reads, and it is the case the function path skips. The virtual function's template bypasses the ACL
by design — it is admin-authored, like a view's SQL — so the *only* gate on it is the call itself.

## Design

- `ResolveFunction` returns the effective capabilities of the grant chain, the same
  `coalesce(object caps, catalog caps)` the relation path already uses (spec 006), unioned across the
  principal's roles;
- the rewriter requires `select` before expanding or retargeting a virtual **table function** and
  before expanding a virtual **scalar function**; the denial names the function, so an operator can
  tell it apart from the function-gate denylist;
- the escape hatch is per-object: `ACL ADMIN GRANT TABLE sales.shout TO ROLE ingest CAPS
  '{"select": true}'` gives read on that one function without giving it on the catalog. This is why
  the gate can be strict — the model already has the granularity to allow a single pure transform.

Non-virtual functions are unaffected: they are gated by name through `PolicyStore::FunctionAllowed`
(the readers/rights-bypass denylist), which is a different question from "may this role read".

### Markers are baked wherever they stand

Writing the test for "a scalar call is a read" needs a template that actually reads — which means a
subquery — and that turned out not to work at all: marker baking walked only a `SELECT` node's own
select list, `WHERE`, `HAVING` and `QUALIFY`, so `acl_claim`/`acl_arg` inside a subquery, inside a
`FROM` clause or on either side of a set operation were left in place. They are never registered as
real functions, so the query failed closed at bind (`Scalar Function with name acl_arg does not
exist`) — safe, but it made perfectly reasonable policy unusable: a predicate over a subquery, a
`UNION` of two tenant slices, an RLS clause with an `IN (SELECT …)`.

Baking now walks every expression of the node through duckdb's own query-node iterator and descends
into subquery expressions explicitly (the iterator stops at their boundary). Fail-closed is unchanged
— a marker that is somehow still missed is still not a function — but the templates an admin would
naturally write now resolve. A `WITH` clause is covered by the same walk: a template's CTE parses into
a subquery ref in the `FROM`, which the old walk skipped entirely. The explicit CTE-node branch next
to it is a guard rather than a live path — no template shape produces that node today, but duckdb's
traversal has no case for it and its default throws, and we track duckdb's `main`.

### Capabilities that were never stated

Making the capability decide raised the question of what a grant that never mentions capabilities
means. Two different things, and the difference is now explicit:

| written | meaning |
| --- | --- |
| `GRANT CATALOG sales TO ROLE r` (no `CAPS`), or a driver row with NULL/empty caps | **every data capability** — `select, insert, update, delete, merge` |
| `GRANT CATALOG sales TO ROLE r CAPS '{}'` | **none** |

A source that hands out a catalog without saying what may be done with it has already made the access
decision; capabilities are how that decision is *narrowed*, so an unstated one is not a refusal. This
is what the function-driver contract needed: a platform whose own resolver decides access can return
grants without caps and have them mean what it intends. `manage` is deliberately **not** part of the
default — administering the ACL is granted explicitly and only explicitly (spec 009).

An **object** grant is a refinement of a catalog grant rather than an access decision of its own, so
an object row that states no capabilities **inherits the catalog's** instead of defaulting to full.
That keeps spec 011's rule intact — a grant may narrow, never widen — so attaching a policy with
`GRANT TABLE sales.orders TO ROLE r RLS '…'` cannot promote the role to every verb by omission. To
lift a capability on one object, state it: `… CAPS '{"select": true}'`.

### Memory backend

The in-memory store (dev/tests) sets `select` on a macro-form function policy but not on an
`alias`-form one, so the gate would deny every aliased function there. Both forms now carry it — an
alias is a rename of a physical function, not a lesser grant.

## Enforcement & security

The gate is applied at rewrite time, before the template is expanded, so a denied call never reaches
bind — its template is not even parsed. Together with spec 003 and spec 011 the rule is now uniform:
**every read of rows or of a virtual definition needs `select` on the object being read**, and the
capability is resolved through the same grant chain in both paths.

## Testing

`test/sql/acl_function_select_gate.test` (75 assertions): a write-only catalog grant denied on a
virtual table function, on a macro scalar, on an alias scalar and on a scalar whose template reads a
table (the leak this closes); the write itself still working, so the grant is narrowed and not broken;
a per-object `select` grant on one function allowing exactly that one while its neighbours stay
denied; the object-level capability of spec 011 overriding the catalog's in both directions; the gate
running before expansion (a denied call to a function with a broken template reports the ACL refusal,
not a binder error); and markers baking inside a subquery, on both sides of a `UNION`, in a
table-function macro's subquery, in a `WITH` clause and in an RLS predicate's subquery. The
capability defaults get their own block: a grant with no `CAPS` reading, writing and calling
functions but still refused ACL administration; an explicit `'{}'` refused everywhere; an object grant
stating nothing inheriting the catalog's capabilities in both directions (it neither lifts a `'{}'`
nor promotes a select-only role attaching a policy). The existing suites (`acl.test`,
`acl_catalog.test`, `acl_functions_driver.test`) prove the memory, catalog and function-driver paths
still resolve their functions.

## Alternatives considered

- **Gate only table functions** (they are unambiguously relations in `FROM`): leaves the scalar path
  as a read channel for a write-only role, since a scalar's template may read any physical table.
- **A separate `execute` capability** for functions: a fourth thing to grant, and the question it
  answers ("may this role read what the function returns") is the one `select` already answers.
- **Classifying scalars into pure/reading** to gate only the reading ones: the classification cannot
  be made from the template text reliably, and guessing wrong is a silent leak.
