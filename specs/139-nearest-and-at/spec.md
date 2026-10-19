# Spec 139: NEAREST and AT expressions are walked like any other

- **Status**: implemented (a security fix found by review 138, 2026-10-19; CLAUDE.md: a gap found in our own code
  gets a fix, a regression test and a line in the spec)
- **Date**: 2026-10-19
- **Author**: Claude (with the owner)

## Summary

duckdb 2.0's grammar added two places in a table reference where an expression lives. The rewriter walked
neither, and neither does duckdb's own `ParsedExpressionIterator`:

- `JoinRef::ranking_expression`, the `BY DISTANCE | SIMILARITY <expr>` of a `NEAREST` join;
- `BaseTableRef::at_clause`, the `AT (VERSION | TIMESTAMP => <expr>)` of a time-travel read.

So a principal could put a subquery over an ungranted source, or a call the function gate refuses, in either place.
duckdb binds the AT expression while it binds the reference, before it learns that the catalog takes no time
travel. Both are now walked like every other expression.

## Problem

These are gate coverage probes, run under a principal that holds `select` on one virtual catalog and nothing else:

- `SELECT … FROM a x JOIN a y EXACT NEAREST 1 BY DISTANCE … + (SELECT n FROM sec.main.secret)`
  - It returned rows, while a direct read of `sec.main.secret` is refused.
  - A `CASE … error()` in the same place tests a value of the source.
- `… BY DISTANCE … + acl_create_catalog('x')::INT`
  - It ran the admin function as the principal: the catalog was created.
- `SELECT * FROM a AT (VERSION => acl_create_catalog('evilcat')::INT)`
  - It ran the admin function; duckdb only failed afterwards with "Catalog type does not support time travel".
  - The same place takes any scalar call: `acl_grant_admin`, `getvariable`.
  - duckdb refuses a subquery in an AT clause by itself.
- In a stored body, `AuthorizeBodies` (spec 117) did not see a call in either place.
  - The AT expression of a view's SQL even ran at write, while the definition was probed.

A sweep of every other place an expression lives found them walked: ORDER BY, LIMIT, DISTINCT ON,
`* REPLACE`, a window frame, QUALIFY, FILTER, VALUES, a recursive CTE with USING KEY.

## Design

- **The rewriter's JOIN case** walks `ranking_expression` (`RewriteExpr`, the same as the condition).
  `duplicate_eliminated_columns` is refused. It is the planner's own field, and the parser never writes it, so a
  statement carrying it is no client's.
- **The rewriter's BASE_TABLE case** walks the AT clause's expression first, before the CTE check, because a CTE
  reference may carry one too. The expression's calls are then gated and its names resolved like any others. A
  constant `AT (VERSION => 3)` over a time-travel source (DuckLake) works as before.
- **`WalkBodyNode`**, the function gate of a stored body, collects both expressions next to PIVOT's.

## Enforcement & security

- **Fail closed:** the default branch of the table-reference switch already refuses an unknown reference kind. This
  spec closes the two fields of known kinds that were missed.
- **No parameters added** (the golden rule): the expressions are rewritten in place.

## Testing

`test/sql/acl_nearest_and_at.test`:

- **Under a principal:**
  - NEAREST over an ungranted source: refused.
  - NEAREST with an admin function: refused.
  - AT with an admin function: refused.
  - A NEAREST join over granted objects: answered.
- **In a stored body**, written by a catalog admin: an admin function in NEAREST, and one in AT, are refused by its
  function gate.
- **The catalog table** shows that none of them made a catalog.

## Follow-ups

- Our walkers that lean on duckdb's iterator miss whatever field the iterator misses:
  - the lineage runtime's;
  - the marker bakers, which fail closed, since a marker left unbaked does not bind;
  - spec 138's reference walker.

  Each now knows the two fields, but a later pin can add a third. A pin bump should re-run the sweep above (the
  probe list in this spec).
