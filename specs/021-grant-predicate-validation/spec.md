# Spec 021: a predicate is checked where it is written

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

A grant's predicate — and an object's own — is bound against the relation it filters **at the moment it
is written**. A predicate that cannot bind is refused there, instead of being stored and failing for
whoever eventually queries the object. That also removes spec 020's last refusal: with the predicate
known to bind against its target, a subquery inside it is no longer a hazard.

## Problem

Two problems, one cause.

**A broken grant was accepted silently.** `RLS (tenat = acl_claim('tenant'))` — a typo — was stored
without complaint and only surfaced as a binder error for the first principal to read the object. The
administrator who made the mistake got no signal at all.

**And a broken grant was worse than broken.** Spec 020 found the one case where such a grant does not
merely fail: a bare correlated reference inside a subquery, naming something the target does not have.
On its own the grant fails to bind (`Referenced column "label" not found`), but in a write with a
second relation in scope that name can resolve to the *source* instead — and the policy silently
evaporates. Spec 020 refused every subquery predicate to stay clear of it; the real fix is to refuse
the grant.

## Design

Before a predicate is stored, it is bound without reading data:

```sql
SELECT * FROM (SELECT * FROM <the object> WHERE (<predicate>)) WHERE false
```

with markers nulled exactly as the schema probe of spec 010 does, so `acl_claim('tenant')` is a typed
NULL rather than an unknown function. The object is the physical relation, or a view's own SQL when the
record is a view.

**The object is bound on its own first.** If *that* fails there is nothing to judge the predicate
against — a policy is often written before its source is attached — and the predicate is accepted
unchecked, exactly as a schema probe that cannot bind is not fatal. This keeps the check from turning
"source not ready" into "your grant is wrong".

**The check binds against the object, not against the grant's projection.** A predicate that filters on
a column the same grant hides is normal and correct — hiding `tenant` while filtering by it is the
common shape — so the projection is not part of this question.

Both write paths are covered: the grant (`acl_grant_object` and the `GRANT … RLS` forms) and the
object definition (`acl_add_relation` and the `CREATE VIRTUAL …  RLS` forms).

### Spec 020's subquery refusal is lifted

`UPDATE … FROM` / `DELETE … USING` / `MERGE` accepted every predicate except one containing a
subquery. That refusal existed only for the broken-grant case above, which can no longer be stored, so
it is gone. The qualifier walk now descends into the *operand* of `x IN (SELECT …)` — which is in the
outer scope and needs the target's name — and leaves the subquery's own body alone, where a bare name
belongs to its own scope.

## Enforcement & security

- The check is a bind, never an execution: `WHERE false` on top, and no row is read. A predicate cannot
  become a way to run SQL as the administrator, because the administrator is already the one running
  it.
- Refusing at write time is a **correctness and operability** improvement, not a new boundary: a
  predicate that failed to bind never granted anything, it only produced errors. The security content
  is the one case it did not fail — which is why spec 020 can now stop refusing subqueries.
- Admin functions are now marked fallible. They refuse at execution time (a bad predicate, a name in
  use, a missing target) and an unmarked scalar function turns every such refusal into
  `INTERNAL Error: … the function is not marked as fallible`, which reads as a crash rather than as the
  administrator's mistake.
- The memory-backed store (no policy catalog) does not validate: there is no database to bind against.
  Its grants are a development convenience and already carry that caveat.

## Testing

`test/sql/acl_grant_validation.test` (38 assertions): a typo refused, the correlated-reference grant
refused with nothing written, an object definition's own predicate refused; a claim marker not
mistaken for a column; a predicate filtering on a column the same grant hides; a legitimate subquery
predicate accepted and then used in an `UPDATE … FROM` (spec 020's lifted refusal); a grant on an
object whose source is not attached accepted rather than refused; and a view's predicate checked
against the view's SQL — `amount` refused, `n` accepted.

`test/sql/acl_multi_relation_writes.test` had the subquery refusal pinned; it now asserts the write
succeeds.

## Alternatives considered

- **Validate at query time instead.** That is where it happened before, by accident, and the
  administrator never sees it. It also cannot help the case that does not fail.
- **Refuse when the object cannot be bound.** Simpler rule, but it breaks the ordinary sequence of
  writing policy before attaching sources, and it would make an unrelated outage (a source briefly
  unreachable) look like a policy error.
- **Parse the predicate and check names against the stored column list** instead of binding. Cheaper,
  but it cannot see through a view's SQL, does not understand subquery scopes, and would have to
  re-implement name resolution — which is exactly what binding does correctly.

## Follow-ups

- The same treatment for a grant's **projection** expressions (`total = amount * 2`): they are probed
  today when the object is defined, but a grant-level projection is not checked the same way.
- Re-validation on `acl_refresh_schema`: a source that drops a column leaves a predicate that no longer
  binds, and nothing notices until a query does.
