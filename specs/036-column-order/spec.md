# Spec 036: a principal's columns have one order

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

A principal holding several roles got its columns in whatever order the policy store happened to
return the grants in, and the metadata listings computed a different order again — same columns, same
types, different sequence. Both sides now follow one rule: **a column belongs where the first role
that names it put it, with roles taken in name order**. So the read path, `DESCRIBE`, the columns
listings and the synthesized DDL agree, and the order of roles inside a token changes nothing.

## Problem

Two ways to see it, and the second is why it matters.

**The order was not defined.** `GrantUnion::Add` merges roles by appending each role's column list and
skipping names already present, so the result is "first role's list, then what the next adds". Which
role is first was decided by `ORDER BY prio` — with no tiebreak, so among the rows of one object the
store's row order won. Nothing pinned it: the same policy could answer in a different order after a
restart, an index change, or a different backend.

**The listing computed its own order.** Spec 035 builds `duckdb_tables().sql` from the columns
listing, whose positions come from the grants' `pos` values. Measured on two roles granting
`(id, tag = tenant)` and `(id, amount, tag = tenant)`:

```text
duckdb_tables().sql  →  CREATE TABLE "orders"("id" INTEGER, "tag" VARCHAR, "amount" INTEGER);
DESCRIBE orders      →  id, amount, tag
```

Same three columns, two different orders — and a spec 035 test happily pinned both, because each was
internally consistent.

**Why it is not cosmetic.** A quack client builds its client-side catalog entry by parsing that DDL,
and its scan then projects **positionally**:

```cpp
query += "#" + to_string(col_id.GetPrimaryIndex() + 1);   // SELECT #1, #3 FROM tbl
```

So a client asking for what it believes is column 2 gets whatever the server calls column 2. With the
orders disagreeing it reads the right *types* from the wrong *columns*, silently — the worst failure
mode available. Flight SQL's `GetTables(include_schema=true)` has the same exposure, since a schema is
an ordered list.

## Design

**The rule**: a principal's columns for an object are ordered by *(the first role, in role-name order,
whose grant states the column; that column's position in that role's list)*. Within one role it is
simply the order the grant was written in; across roles it is deterministic and independent of the
token.

Role-name order is the choice worth stating: it is stable across restarts and backends, it does not
depend on how a token happened to list its roles, and it is explainable to whoever writes the policy.

**The read path** gets the tiebreak it was missing: the three queries that merge rows of several roles
— relation lookup, schema-alias lookup, function lookup — now order by `prio, g."role"` (the alias
lookup keeps its longest-prefix tiebreak in front). `GrantUnion::Add` is unchanged: fed in role order,
its existing append-and-merge produces exactly the rule above.

**The listing** reproduces the same sequence rather than approximating it. The projection CTE ranks
each object's grant columns by `(role, pos)`, takes each name's first occurrence, and re-numbers the
survivors with `row_number()`:

```sql
gprojection AS (
  SELECT vcat, vname, name, type,
         row_number() OVER (PARTITION BY vcat, vname ORDER BY rk) - 1 AS pos
  FROM (SELECT vcat, vname, name, min_by(type, rk) AS type, min(rk) AS rk
        FROM (SELECT …, row_number() OVER (PARTITION BY vcat, vname ORDER BY "role", "pos") AS rk
              FROM grant_columns pc JOIN grants g …)
        GROUP BY vcat, vname, name))
```

Ranking by `(role, pos)` and keeping the first occurrence *is* the merge; the outer `row_number()`
closes the gaps a merged duplicate leaves behind, so positions are 1..N with no holes — which matters
because a consumer counts them.

## Enforcement & security

- **Nothing about visibility changes.** Which columns a principal sees is decided by the same filters
  as before; this spec decides only the sequence. The suite that pins visibility passes unchanged.
- **The failure this closes is a confusion, not a leak** — a positional client reading column 2 as
  column 3 sees data it is allowed to see, under the wrong name. That is still a correctness bug
  worth closing before a door ships that projects positionally.
- **Deterministic beats clever**: role-name order is not the "best" order by any semantic measure, but
  it is the one both sides can compute without sharing state, which is what makes the agreement hold.

## Testing

`test/sql/acl_column_order.test` (42 assertions):

- two roles with overlapping lists that place the shared column differently — `SELECT *`, `DESCRIBE`,
  `duckdb_columns()`, `information_schema.columns` and the synthesized DDL all give `id, tag, amount`;
- the same principal presented with its roles in the **other order** in the token gives the same
  answer;
- positions are `1,2,3` with no gaps where a duplicate was merged away;
- a single role whose grant reorders the table and adds a computed column (`note, initial = tenant,
  id`) keeps its own list order everywhere;
- one role restricting while another states nothing — the object's own columns, with no phantom
  projection column and no repeated position;
- an object with no grant projection keeps the object's own column order.

Full suite: 38 files, 3094 assertions, both C++ binaries.

### A defect the self-review found

Fixing the order exposed a worse neighbour. Where one role stated a column list and another stated
none, the read path applied spec 011 — a grant that says nothing does not narrow, so the principal
reads the object's own columns — while the listing still unioned in the restricting role's
projection:

```text
read path →  id, tenant, amount, note
listing   →  id@1, tenant@2, tag@2, amount@3, note@4
DDL       →  CREATE TABLE "orders"("id" …, "tenant" …, "tag" …, "amount" …, "note" …);
```

A phantom column that `SELECT *` never returns, at a position colliding with a real one — and a
client binding that DDL and projecting positionally would have read nonsense. The projection CTE now
drops out entirely for an object where any granting role's chain states no column list, which is the
same rule `Restricts()` applies on the read path.

## Alternatives considered

- **Order by the underlying object's columns, computed ones last.** Closer to what a table "looks
  like", but a grant's list order is written deliberately and this would discard it — and computed
  columns would still need a tiebreak among themselves.
- **Order by the token's role order.** The principal would get different column orders from two
  tokens carrying the same roles, which is worse than any fixed rule.
- **Sort columns by name.** Deterministic and useless: it destroys the author's ordering and moves
  every column whenever one is added.
- **Leave the read path and make the listing follow it.** The read path's order was not *knowable* —
  it depended on the store's row order — so there was nothing for the listing to follow.

## Follow-ups

- The merge only applies when the roles state column lists. Where one role restricts and another does
  not, the unrestricted role lifts the restriction (spec 011) and the object's own order applies —
  covered by a test, but the interaction deserves its own look when write paths use this ordering.
- Role names are compared by the store's collation, not by ours. For ASCII role names the two agree;
  a deployment with non-ASCII role names on an exotic backend could in principle see the listing and
  the read path disagree, since the listing sorts in SQL and the merge consumes that order directly.
  Both read the same `ORDER BY`, so this is a theoretical note rather than a known divergence.
- An object whose roles mask one name with different expressions is still unreadable but still listed
  (spec 035 follow-up). Ordering does not change that.
