# Spec 159: a policy text binds only to its own source

- **Status**: implemented
- **Date**: 2026-11-13
- **Author**: hugr lab (found by spec 157's review)

## Summary

The SELECT a principal reads a virtual object through holds the policy's texts: the RLS, the masks, the computed
columns, the view's SQL, or a table function's template. Before the statement is optimized, that SELECT is now bound
as a statement of its own. A name its source lost refuses there, instead of binding to a column of the principal's
query.

## Problem

The rewriter replaces a virtual object with `(SELECT … FROM <phys> WHERE <rls>) AS <name>` in the principal's query.
duckdb binds a subquery's names inside out, so a name the subquery cannot resolve itself binds to an outer scope:

- **A relation before it in the FROM.** duckdb makes the subquery an implicit LATERAL join. With the RLS column
  dropped from the source, `region = 'eu'` bound to the earlier relation's `region`:
  `SELECT logs.* FROM (SELECT 'eu' AS region) s, logs` read every row the RLS hid.
- **A correlated subquery.** `SELECT (SELECT count(*) FROM logs) FROM (SELECT 'eu' AS region) s`.
- **A write's target.** `DELETE FROM w WHERE id IN (SELECT id FROM logs)` bound the RLS to `w.region`.

The same held for a mask (`secret = note` read the principal's own `note`), for a subquery inside an RLS, for a
view's SQL and for a table function's template. Each needs a drift: a name the source no longer has, until the
operator mends the object.

## Design

Every policy read the rewriter emits is noted on the statement (`ReadRef`, acl_rewriter.cpp, beside spec 157's
`NoteReadableGuard`). That covers both read builders, `BuildTableSubquery` (a projection, an RLS, a view) and
`BuildRenamedSubquery` (a rename or a cast). It also covers a virtual table function called with closed arguments
(`ClosedArguments`: constants only - no column, subquery, lambda, star or parameter, which a bind alone cannot
take). The read is its SQL with the
markers baked. The read stays where it was: the statement, its plan and a scanner's pushdown do not change.

Spec 157's mechanism, keyed by content:

- Each read is kept under the hash of its text (`WriteGuardKey`: 128 bits of SHA-256) in `PolicyStore::write_guards`.
  The same read is one entry whoever reads it. A table function's constants are part of its read, so distinct
  constants are distinct entries: the registry is bounded by count (65536) and by bytes (64 MiB), least recently
  used first.
- The keys go at the end of the statement's text: `/* acl:guard:<key>,… */`, on a line of its own, and on each part
  of a `MultiStatement`. Every execution of a prepared statement carries them.
- `QueryBegin` takes the keys off the running text. `WriteGuardPreOptimize` binds each read with a binder of its own,
  in the statement's context and transaction.

A read that binds alone has no name left to bind to the principal's: inner scopes bind first, and every name of the
read resolves inside it. A read that does not bind refuses the statement, with the read's own error as spec 155 cuts
it. A key no longer in the registry refuses too ("this statement's decision is no longer known - run it again"),
fail closed.

Spec 157's own keys (a write's target) became content keys as well. A per-decision token minted one entry per parse,
and a principal could flood those.

## Enforcement & security

Fails closed: a marked statement runs only after every read of its policies binds alone. Nothing is executed for
them. The binder reads the catalog the statement's own bind reads.

The keys are found on the text the statement runs under (`GetCurrentQuery`). A gateway or a door runs a
principal's statement through `Query` / `Prepare`, which keep that text. duckdb's relation API (`RelationFromQuery`)
runs `ToString()` of the statement instead, which drops the marker, so a gateway must not run a principal's statement
through it. Only the connection's holder, the trusted side, reaches that API.

Not covered here (Follow-ups):

- **A virtual scalar's template.** It is an expression in the principal's scope.
- **A table function called with the principal's columns or a parameter** (`FROM t, f(t.x)`, `f($1)`). The first is
  correlated on purpose; a parameter cannot be bound alone.
- **Shadowing.** A principal's CTE or temp table named like a table that a policy names unqualified: binding alone
  sees the catalog's table, the statement sees the principal's. That is spec 160's.
- **Optimizer extensions off.** This has spec 157's known limit: `enable_optimizer = false`, or `disabled_optimizers`
  naming `extension`, skips the check. Those settings are the operator's, never a principal's.

## Testing

`test/sql/acl_policy_own_source.test`. After the source dropped the columns an RLS and a mask read:

- **Reads refuse:**
  - a relation before the object;
  - a correlated subquery;
  - a subquery inside the RLS;
  - a view's SQL;
  - a mask.
- **Writes refuse, and no row goes:**
  - `DELETE … USING`;
  - `IN (SELECT …)`;
  - `UPDATE … FROM`;
  - a write with a CTE of the principal's;
  - a `MERGE` source;
  - `INSERT … SELECT`;
  - a write whose own target has the lost name.
- **Table functions:** the lateral and correlated forms refuse.
- **Unchanged reads:** a policy that binds reads as before beside a relation, in a CTE, in a correlated subquery and in
  a `UNION`.

Each form returned the hidden rows before. The plan is the old one: nothing in the statement changed but a comment.

## Alternatives considered

- **Hoisting each read into a `NOT MATERIALIZED` CTE at the statement's root.** A root CTE body has no outer scope,
  and that would also have stopped CTE shadowing. The review measured it: under a correlated subquery or a LATERAL
  join, duckdb keeps such a CTE materialized when the source's scan cannot be copied (Postgres, MySQL). The
  principal's filters then no longer reached the source: 50,000 rows read instead of 9. A `WITH` around a write also
  broke mysql_scanner's whole-statement pushdown.
- **Qualifying every policy column with an alias only the read has.** Not complete: a nested subquery whose names
  reach past its own FROM, a view's SQL.
- **A CTE local to the read's subquery.** duckdb binds its body with the subquery's outer scope; it leaked the same.
- **Spec 157's per-decision token.** One entry per parse, so a flood evicted a long-lived prepared statement's entry.

## Follow-ups

- **Spec 160 (built): a policy's tables are written whole.** Qualified where written, a policy's table is never a
  principal's temp table's or CTE's.
- **A principal's own view (spec 113)** stores its rewritten body, and a read of it is bound alone as one read. Its
  body should be rewritten with the same guards as a statement's.
- **`acl_arg`**: a call's argument is spliced into the template's physical SQL. It should be evaluated in the caller's
  scope, with only its value reaching the template.
- **`AT (VERSION => …)` on a virtual object is dropped silently**: noted under the BACKLOG's "RLS for versioned
  tables".
