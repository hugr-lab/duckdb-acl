# Spec 020: writing with a second relation in scope

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

`UPDATE … FROM`, `DELETE … USING` and `MERGE` were refused on a narrowed target — *"is narrowed by a
grant, so it cannot be written with FROM/USING/MERGE yet"*. They are allowed now: the grant's
predicate is **bound to the target by name** rather than merely AND-ed into a condition, and every
`MERGE` branch that can touch a target row carries it.

## Problem

With one relation in scope, ANDing `tenant = acl_claim('tenant')` into the `WHERE` clause is enough —
the only `tenant` in scope is the target's. With a join, an unqualified reference can bind to the
*source* instead, and then the predicate silently filters the wrong rows: a source whose `tenant`
column happens to hold something else would let the statement through against every target row, or
none. Refusing was the honest placeholder; it also made `MERGE` unusable for the case it exists for.

`MERGE` has a second problem that `UPDATE`/`DELETE` do not: it has no `WHERE`.

## Design

**References are attributed by qualifier, not by name.** Two mappings run over a write, and both were
name-only, which is correct with one relation in scope and wrong with two:

- The *principal's* references (`WHERE`, `SET`, `ON`, `RETURNING`) go through the rename map, which
  used to rewrite any reference whose last component matched — so `feed.id` was refused as
  `"renamed" has no column "id"` because `id` is the physical name behind `order_id`. A join on `id`
  is about as ordinary as SQL gets, and it could not be written at all. Now a reference qualified by
  anything other than the target's alias is left alone.
- The *grant's* predicate is qualified with the target's alias.

**The predicate is qualified with the target's alias.** Spec 019 made the target answer to the virtual
name (or the principal's own alias), so there is a name to bind to. Every bare column reference in the
grant's predicate is qualified with it before the predicate is AND-ed in, so a same-named source column
cannot capture it. This applies only when a second relation is in scope; the single-relation forms are
left exactly as they were.

**`MERGE` carries the predicate in two places**, and both are needed:

- **The `ON` clause.** A target row outside the grant then never matches, so no `WHEN MATCHED` branch
  can reach it.
- **Every `WHEN NOT MATCHED BY SOURCE` branch.** This is the subtle half: once the predicate is on the
  `ON` clause, a row outside the grant is *not matched*, which is precisely the set this branch acts
  on. An unguarded `WHEN NOT MATCHED BY SOURCE THEN DELETE` would therefore delete exactly the rows the
  grant exists to protect. Each such branch gets the predicate as its own condition.

**The `INSERT` branch of a `MERGE` carries the column policy**, like a plain `INSERT`: only granted
columns may be written, and an injected value is assigned rather than supplied — the branch's column
list and expressions are rewritten in place. Without an explicit column list (`INSERT BY NAME`,
`DEFAULT VALUES`, no columns) there is nothing to check the grant against, so it is refused with that
message. The `UPDATE` branch gets the same treatment as a plain `UPDATE`: written columns are checked
and injected columns re-assigned.

**`MERGE`'s `RETURNING` is now gated** by the same rule as every other read — it was not, because a
narrowed target could never reach a `MERGE` before.

## Enforcement & security

- **Predicate capture** is the specific risk this spec exists to close, and the test builds the trap
  deliberately: the source has a `tenant` column holding a different value, so a captured predicate
  would produce a visibly wrong result rather than a plausible one.
- **`WHEN NOT MATCHED BY SOURCE`** is tested against a row outside the grant: it survives a `DELETE`
  the principal issued for it.
- **Still refused**: a grant whose **predicate contains a subquery**. Measured rather than assumed — a
  non-correlated subquery predicate (`id IN (SELECT id FROM allow)`) behaves correctly with a join, and
  a correlated bare reference whose name exists on both sides is caught by DuckDB itself
  (*"Ambiguous reference to column name"*), writing nothing. The one case that does go wrong is a bare
  correlated reference to a name the **target does not have** but the source does: the predicate binds
  to the source and the policy evaporates. Such a grant is already broken — in the single-relation form
  it fails with `Referenced column … not found` — so the real fix is not here (see follow-ups). Until
  it exists, the refusal stays.

### A consequence worth stating: upsert against an invisible row

With the predicate on the `ON` clause, a target row outside the grant never matches, so a source row
that "should" have updated it is *not matched* and the `INSERT` branch inserts alongside it. The
principal is not told that the other row exists, and cannot read or write it — but the table can end up
with two rows sharing a key. This is inherent to row-level security plus upsert (PostgreSQL behaves the
same way), not something this design chose.

Where the physical table has a unique constraint on that key, the insert fails on the constraint
instead, and the failure does disclose that *some* row with that key exists outside the principal's
slice. That is a narrow existence leak with no way to close it at this layer; a deployment that cares
should not grant `merge` on a table whose key space is shared across tenants.

## Testing

`test/sql/acl_multi_relation_writes.test` (79 assertions): `UPDATE … FROM` and `DELETE … USING`
against a source carrying a same-named column, with rows outside the grant left untouched and the
principal's own rows written; `MERGE` with `WHEN MATCHED`, `WHEN NOT MATCHED BY SOURCE` (the row
outside the grant survives) and `WHEN NOT MATCHED THEN INSERT` (tenant assigned by the grant, insert
alongside the invisible row); an ungranted column refused in the insert branch; an injected column
assigned rather than suggested in the update branch; `INSERT BY NAME` refused; `RETURNING` gated; and
a renamed target written through a join (the source's `feed.id` reaching the source while
`renamed.order_id` reaches the target, for both `UPDATE … FROM` and `MERGE`), with the physical name
still refused to the principal; and the subquery-predicate refusal, with the single-relation form still
working for the same role.

`acl_grant_policy.test` and `acl_dml_qualification.test` had assertions pinning the old refusal; they
now assert the new behaviour.

## Alternatives considered

- **Wrap the target in a subquery**, as the read path does. Impossible: a DML target must be a real
  table, which is why the policy has to travel as a predicate at all.
- **Refuse `WHEN NOT MATCHED BY SOURCE` when narrowed** instead of guarding it. Simpler, but it removes
  the branch that makes `MERGE` a synchronisation tool, and the guard is one AND.
- **Qualify predicates everywhere, including single-relation writes.** More uniform, but it rewrites
  the generated SQL for every existing statement to no benefit — there is nothing to capture a
  predicate when only the target is in scope.

## Follow-ups

- **Validate a grant's predicate when the grant is written.** Today a predicate that cannot bind
  against its own target is accepted silently and only fails for whoever uses it — and it is exactly
  such a grant that turns permissive under a join. Binding it once at write time (the machinery of
  spec 010 already does this for templates) rejects it at the source and removes the only reason the
  subquery refusal exists.
- An unqualified reference whose name belongs to both the target and the source is resolved to the
  target rather than reported as ambiguous. Ambiguous SQL, resolved one way; qualifying is the answer,
  and it may be worth refusing instead.
