# Spec 075: PIVOT and UNPIVOT under a principal

- **Status**: implemented
- **Date**: 2026-09-17
- **Author**: hugr lab

## Summary

`PIVOT` and `UNPIVOT` were refused as forms - the explicit `PivotRef` as "table reference form is
not permitted", the implicit `PIVOT t ON col` as "statement type MULTI is not permitted". Both are
admitted now, through the gate that everything else goes through: the source is a relation like any
other (resolved, confined by RLS, masked), everything the pivot computes over it is an expression like
any other (gated), and the implicit form's column discovery - a `CREATE TEMP TYPE ... AS ENUM (SELECT
DISTINCT ...)` the parser emits ahead of the pivot - runs under the same confinement, so a value only
a hidden row carries never becomes a column.

## Problem

Wide-to-long and long-to-short reshaping is what an analyst's tool sends after `SELECT`, and the
owner asked for it to work rather than be refused. Refusal was the safe default because a pivot
carries expressions and reads in places the walker did not visit: the `USING` aggregates, the `ON`
expressions, an `IN (...)` list's entries or `IN (SELECT ...)` subquery, the source itself - and for
the implicit form a whole separate statement that reads the source before the pivot binds.

## Design

**Two shapes arrive from the parser.**

- `SELECT ... FROM t PIVOT (agg FOR col IN (...))`, `PIVOT t ON col IN (...) USING agg`, and every
  `UNPIVOT` - a `SelectStatement` whose FROM is a `PivotRef`: `source`, `aggregates`, per pivot column
  its `pivot_expressions`, `entries` (each a value or an expression - `COLUMNS(*)` for UNPIVOT) and an
  optional `subquery` for `IN (SELECT ...)`; `groups` and `unpivot_names` are identifiers.
- `PIVOT t ON col USING agg` with no IN list - a `MultiStatement`: duckdb discovers the column set from
  the data first, so the parser emits one `CREATE TEMP TYPE __pivot_enum_<uuid> AS ENUM (SELECT DISTINCT
  CAST(col AS VARCHAR) FROM <source> WHERE col IS NOT NULL ORDER BY 1)` per pivot column, then the
  SELECT whose `PivotRef` names the enum (`peg_transformer.cpp`, `CreatePivotStatement`). The type is
  temporary, unqualified, `REPLACE_ON_CONFLICT`, and lives in the connection's temp catalog.

**Rewrite.** `RewriteTableRef` gains `TableReferenceType::PIVOT`: the source goes through
`RewriteTableRef` (RENAME or SUBQUERY form, RLS, masks - as in any FROM), the aggregates, the pivot
expressions and the entry expressions through `RewriteExpr` (the function gate, virtual scalar
functions, the identity substitution), an `IN (SELECT ...)` subquery through `RewriteQueryNode`. Names
bind against the rewritten source, so a column the grant does not list is not there to pivot on.

`RewriteStatement` gains `MULTI_STATEMENT`: every statement but the last must be the parser's enum step
- `IsPivotEnumCreate`: a `CREATE` of a `TYPE_ENTRY` that is temporary, unqualified, named
`__pivot_enum_*` and defined by a SELECT - and its query is rewritten with `RewriteQueryNode`; the last
must be a SELECT and is rewritten as one. Anything else in a multi-statement is refused with the
statement type it is (ALTER's multi forms come this way and stay refused). The audit's statement
class for the whole is `pivot` - what the principal wrote, not the shape the parser gave it.

**What this is not.** A `CREATE TYPE` a principal spells by hand - `__pivot_enum_` prefix or not - goes
through `RewriteCreateStatement` and is refused there as it always was; the enum step is admitted only
as the parser emits it, inside the multi-statement, where its query is ours to rewrite.

## Enforcement & security

- The source is a read like any other: an ungranted or physical name is refused where it is named
  (`PIVOT phys.main.sales ...`, `IN (SELECT ... FROM phys.main.sales)`), RLS confines the rows the
  aggregates see AND the rows the enum step sees, a mask is what the aggregate reads (`sum(masked)` is
  NULL), a column outside the grant's list is a binder error.
- The implicit form's column set is the principal's: unprefixed, a `q9` that only a hidden row carries
  is a column; under the principal there is no `q9` - not as a column, not as a NULL. The explicit
  form with `IN ('q9')` has the column because the caller named it, and a hidden row still feeds it
  nothing.
- Every expression position of a pivot is gated - `USING max(getvariable(...))`, `ON col ||
  getvariable(...)`, the SQL-standard aggregate - pinned beside the other positions in
  `test/sql/acl_expression_positions.test`.
- A refusal in the enum step refuses the statement before anything runs: the temp type is never
  created, so nothing stale answers a later pivot under a wider grant.
- Golden rule kept: the rewriter adds no parameters. (duckdb itself refuses parameters in an implicit
  pivot's source - `PIVOT ... ON col IN (val1, ...)` is its own advice - so nothing changes there.)
- The temp enum types are duckdb's: one per implicit pivot, UUID-named, in the connection's temp
  catalog until the connection ends - on a gateway's shared connection they accumulate as they would
  on any long-lived duckdb connection running pivots. Not ours to sweep; noted in Follow-ups.

## Testing

`test/sql/acl_pivot.test`: the implicit form under RLS (the hidden row's `q9` is no column, checked by
value and by `DESCRIBE`), the audit class `pivot` with the source as its object, the explicit list with
a hidden value named, the SQL-standard form, `IN (SELECT ...)` over the virtual and refused over the
physical source, a masked column's aggregate, a hidden column refused at bind, UNPIVOT in its three
spellings with `COLUMNS(*)` seeing only the granted columns, the gate in the aggregate, the ON
expression and the source of each form, `CREATE TYPE` by hand refused with and without the prefix,
and the same pivot answering with the hidden row once the grant no longer hides it.
`test/sql/acl_expression_positions.test` pins the pivot positions beside the other forty.

## Alternatives considered

- **Keep refusing, tell users to write the aggregate + CASE by hand.** Works, and is what the tools
  would not do; the whole point of the gate is that ordinary SQL goes through it.
- **Rewrite the implicit form into the explicit one.** Would need the distinct values at rewrite time,
  which is a read the rewriter must not do (spec 065: nothing on the query path looks at the source).
  The parser's own enum step is that read, done by the engine, and rewriting its query is enough.
- **Admit `CREATE TYPE` for temp enums generally.** No: the only reason the enum step is safe is that
  its query is ours to rewrite and its name is the parser's; a principal's own `CREATE TYPE` has no
  such story and stays refused.

## Follow-ups

- The Flight door prepares every statement (spec 047), and duckdb cannot prepare a multi-statement
  ("Cannot prepare multiple statements at once!") - so the implicit form is refused there with
  duckdb's own error, exactly as it is on a plain duckdb `Prepare`; the explicit forms and UNPIVOT
  prepare fine. A door-side fallback to a direct `Query` for the implicit form is possible later.
- The parser-made temp enum types outlive the pivot; a sweep on the gateway connection is duckdb's
  question, not ours.
