# Spec 022: references — declared join paths between objects

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

Introspection showed a principal its objects and their columns, but nothing showed how those objects
join. A **reference** fills that in: a named, declared join path between two objects of a virtual
catalog — how to write the join, not a constraint that anything is enforced by. It is read, never
acted on, and it is visible only when both of its ends and every column it names are visible.

## Problem

An agent that can list `orders` and `customers` still cannot tell that one joins to the other, and no
existing surface can tell it:

- **Physical foreign keys are the wrong source.** The virtual catalog renames and hides columns, so a
  physical FK names columns a role may not see. Views and table functions have no FKs at all — and a
  join between a mart and a lookup is exactly what is most often needed. And half the sources
  (parquet, DuckLake) have no FKs to report.
- **A reference can cross sources.** A join between a PostgreSQL table and a DuckLake one cannot exist
  anywhere physical; the virtual catalog is the only place it can be expressed.

## Design

**Names are virtual on both sides.** `FROM c.orders TO c.customers` are virtual object names and
`ON (customer_id = id)` are virtual column names — what a role sees. This is what makes visibility
checkable at all, and it keeps physical names out of a listing.

**A reference is a hint, and only a hint.** Nothing consumes it automatically: no join is rewritten,
no name is substituted, nothing is granted by it. An agent reads it and writes its own query. Every
simplification below follows from that.

### The record

| field | meaning |
| --- | --- |
| `name` | unique in the catalog; one pair of objects may have several (`orders.customer`, `orders.billing_customer`) |
| `from_vname`, `to_vname` | the two ends, as virtual names |
| `to_kind` | `relation` or `function` |
| arguments | for a function end: parameter => source column, the substitution |
| pairs *or* `expr` | how they join — column pairs, or arbitrary SQL. Exactly one of the two |
| `cardinality` | `many_to_one`, `one_to_many`, `one_to_one`, `many_to_many` |
| `optional` | whether the far side may be absent |
| `join_method` | `asof`, `positional`, or nothing |
| `comment` | part of the payload, not decoration — a path is chosen by meaning as much as by column names |

**Both a pair list and an expression are needed, for different reasons.** Pairs are the form whose
visibility is a cheap lookup and which maps to ordinary FK-shaped tooling. An expression is the escape
hatch for inequalities, composite conditions and casts between sources.

**The columns are stored as rows, one per column per side** — including for the expression form,
whose SQL is parsed when it is written and whose column references are attributed to a side by their
qualifier. So `'orders.amount >= rates.rate'` stores `from: amount` and `to: rate`, and visibility is
the same anti-join for both forms. An expression must qualify every column: without a side there is no
way to tell whose column it is, and so no way to check it against what a role sees.

**`ASOF` earns its place; `INNER`/`LEFT` does not.** An `ASOF` join takes one nearest match, while the
same condition as a plain join fans out — that is a different answer, not a slower one, so for
time-shaped relationships the join method *is* the relationship. `INNER` vs `LEFT`, by contrast, is a
consequence of whether the far side is mandatory, which `cardinality` and `optional` already say;
storing both invites records that contradict themselves. Planner hints, multi-hop paths and filters
inside a reference are all out: **a reference describes a join predicate and its shape — never a
projection, an aggregate or a filter.**

### The ends: a relation, a view, or a table function

A **view** needs nothing special. It is a relation of the catalog like any other, its columns come
from the write-time probe, so both the existence check and the visibility check reach it unchanged.

A **table function** is different in kind: it takes *arguments*. One rule covers every shape of that,
and it is the same rule as a function call anywhere else — **the parenthesis after the name is the
argument substitution, and `ON` is the join condition**:

```sql
TO FUNCTION orders_of(cust => id)                                   -- pure substitution, no condition
TO FUNCTION all_orders ON (id = customer_id)                        -- no arguments, join on the result
TO FUNCTION orders_of(cust => id) ON (city = dest)                  -- both
```

`cust => id` reads *parameter => source column*, the direction SQL already uses for named arguments.
An argument's source column is a `from` column for every purpose — it must exist, and it must be
visible — and it carries the parameter it feeds alongside it. `ON`, for a function end, names columns
of the function's **result**, which the catalog stores whether they were declared with `RETURNS TABLE`
or probed at write time. A condition may be omitted only when arguments are the whole relationship.

**Nothing here is bound.** The parameters come from the declared signature, the result columns from
the stored schema. A table function's template carries `acl_arg(n)` markers whose result depends on
the arguments, so it cannot be typed from NULLs (spec 010 says as much), and binding it would prove
nothing the declaration does not already say. A function that declares no signature simply cannot be
judged on its parameters, and is accepted.

A function may only be the `to` end: arguments come from the row on the left.

### Visibility: both ends, every column

A reference is visible to a principal when both of its ends are — an object it may read, or a table
function it may call, which is granted the same way — and when every column it names is one the role
can see, arguments included. Otherwise it would announce an object the role has no access to, or name a
column a projection hides and suggest joining on it.

There is no capability on a reference and no separate grant: it opens nothing, so its visibility is
derived. **No visible columns, no reference** — there is no partial form. Joining past a hidden key is
a thing to do with a view, which is resolved with its author's rights (spec 018) and can therefore
reach a column it never exposes.

Visibility is computed **online**, not materialised per role, because it depends on the grants of both
ends, their projections, the schema grants, the catalog grant and the columns the source last had —
a much wider invalidation front than the one materialised in spec 015, for a listing asked once before
a query is written.

### The surfaces

- **For a principal**: `acl_references()` — every visible reference — or `acl_references('orders')` for
  the ones touching one object, which is what an agent asks before writing a query. It is substituted
  in the rewriter *before* the function gate, exactly as `duckdb_tables()` is, so it needs no hole in
  the gate that denies every other `acl_*` name.
- **For an operator**: `acl_references()` and `acl_reference_columns()` as ordinary introspection
  listings (spec 010 part 3) in the native path — the stored rows, unfiltered.

The two share a name and differ in shape, which is the same arrangement the metadata surfaces already
have: what a principal sees under a familiar name is their own catalog.

### Written where it is written

Following spec 021: a reference that cannot be true is refused when it is declared, not when it is
read. Both ends must exist. Every column must exist on its side — looked for in the declared
projection first (which is where a rename lives), then in the probed schema, and finally by binding
the physical relation for a plain alias, whose columns the catalog does not store. If none of the
three can answer, the reference is accepted, exactly as spec 021 accepts a predicate whose source is
not attached.

## Enforcement & security

- A reference grants nothing and is enforced nowhere. The test asserts both: the far side of a visible
  reference is still refused to a role without a grant on it, and a column the grant hides is still
  unreadable through the object that names it.
- **A leak was fixed on the way.** `information_schema.columns` did not honour a *grant-level* column
  projection (spec 011) — only the object's own. A role granted `COLUMNS (id, customer_id, amount)`
  read three columns and was shown four, including the one the grant hid. The listing now narrows by
  the grant chain as the query path does: a column survives when, for at least one of the principal's
  roles, every level that states a list keeps it. Reference visibility rests on that, so it had to be
  right first.

## Testing

`test/sql/acl_references.test` (102 assertions): declaring both forms and reading back the columns
extracted from an expression; refusals at write time (an end that does not exist, a column that does
not, an unqualified expression, an expression naming neither end, an unknown cardinality, a name in
use); a role seeing both references and narrowing to one object; a role seeing neither the reference
into an object it cannot read nor the one over a column its grant hides — with that column also gone
from `information_schema.columns`; the reference granting nothing; drop, `IF EXISTS`, and the
principal's surface being substituted rather than gated; a view as an end needing nothing special, a
a table function end in its three shapes — substitution alone, a join on the result alone, and both —
with the parameter checked against the declared signature and the condition against the stored result
columns, arguments refused for a relation end, and a role that cannot call the function not seeing the
reference into it while the one between two relations stays.

## Alternatives considered

- **Expose references as `information_schema.referential_constraints`.** Tempting for ORMs and BI, but
  they read a constraint as a guarantee of integrity and may plan or migrate on it. Ours guarantees
  nothing. Deferred until something actually needs it, and then only where "not enforced" can be said.
- **Let a reference be usable, not only readable** — `JOIN … USE ref_name` substituting the condition,
  so a role could join past a hidden key. It cannot be done by substituting a condition: the key must
  be in scope for the join and out of scope for the projection, which is one scope. It would mean
  replacing the whole join with a subquery, and it would turn visibility into a separate grant. A view
  already does this, correctly.
- **Materialise visibility per role at grant time**, as spec 015 does for schema capabilities. Rejected
  above: a much wider invalidation front for a listing that is read rarely.

## Follow-ups

- **Import physical foreign keys** as a starting set: read the source's FKs, map them through renames,
  drop the ones whose ends are not in the catalog or whose columns are hidden. The same shape as a
  schema expansion, with the same `REFRESH` and idempotency.
- **Cross-catalog references**: today both ends live in one virtual catalog.
- **Many-to-many through a junction**: expressible as two references; a single record naming the
  junction may read better.
