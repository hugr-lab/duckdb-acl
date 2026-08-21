# Spec 027: a write-time check that was skipped is remembered, and taken again

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

Spec 021 checks a predicate where it is written, and accepts it unchecked when the object it filters
cannot be bound there. Spec 026 does the same for a grant's projection. Neither recorded *which* of
the two happened, so "this predicate was judged and is fine" and "nothing ever looked at it" were the
same state — and nothing ever looked again. Both now carry a verdict, `acl_refresh_schema` takes the
check again, and the one place that depended on the check refuses a predicate that never got one.

## Problem

Three gaps, all from the same shape:

1. **The verdict was thrown away.** `PredicateError` returns an empty string for "it binds" and for
   "there was nothing to bind it against". The caller could not tell them apart, so neither could
   anything downstream.
2. **Spec 020's subquery rule leaned on a check that may not have happened.** When a write has a
   second relation in scope (`MERGE`, `UPDATE … FROM`, `DELETE … USING`), every bare column of the
   grant's predicate is qualified with the target's alias — except inside a subquery, whose body keeps
   its own scope. That is correct *because* the predicate is known to bind against its target: a name
   in there resolves to the subquery's own FROM or to the target, and nothing else. Without the check
   it could resolve against the source relation instead and silently filter the wrong rows.
3. **Nothing was ever re-probed.** `acl_refresh_schema` re-derived view and macro schemas and stopped
   there. An object registered before its database was attached — the ordinary bootstrap order — kept
   an unjudged predicate and an empty `grant_columns` for the life of the catalog, so the metadata
   surface described the physical table rather than what the role reads.

## Design

**Schema v10 adds `rls_checked` to `relations`, `role_object_caps` and `role_catalogs`**, with three
states: `NULL` — no predicate, nothing to judge; `true` — bound against the object and accepted;
`false` — there is a predicate and nothing judged it (or it was judged and failed, see below). A row
written before v10 reads `NULL` with a non-empty predicate, which the resolver treats as unchecked:
fail closed, and a refresh fills the verdict in.

**The verdict travels the whole grant chain.** `GrantPolicy::Narrow` takes the level's flag alongside
its predicate, `GrantUnion` ORs the roles' predicates and ANDs their verdicts — with the one exception
that matters: a role *without* a predicate lifts the restriction entirely, and an absent predicate
cannot have gone unchecked. `TablePolicy::rls_unchecked` is what the rewriter sees.

**The catalog level is judged against every object it filters.** A catalog grant's predicate has no
single object to bind against, so `CatalogPredicateChecked` binds it against each relation of the
catalog and reports `true` only when every object that binds at all accepted it. Unlike an object's
own predicate this never *refuses* the write — a catalog predicate that does not fit one object is a
real, if questionable, configuration, and it was allowed before the flag existed.

**One refusal, exactly where the assumption lives.** `TargetPredicate` — used only by the four
multi-relation write paths — refuses a predicate that contains a subquery *and* was never checked.
A read is unaffected (the binder decides, and a wrong name errors), and so is a single-relation write
(the target is the only relation in scope). The message says how to fix it: refresh with the object
reachable, or rewrite the grant.

**`acl_refresh_schema` takes both checks again** — every relation's own predicate, every object
grant's predicate and projection, and every catalog grant's predicate — and returns them in its count.
The grant-projection probe is now one helper shared with the write path, differing only in `strict`:
where a projection is written, one that cannot bind is a mistake worth refusing; on a refresh it is
only a fact that has not become true yet. `ProjectionSchema` had the same blind spot as
`PredicateError` — an empty error for "it binds" and for "there was nothing to bind against" — so it
reports which, and a refresh that cannot re-probe leaves the earlier rows alone instead of clearing
them. Without that a refresh run while a source was detached would empty `grant_columns` for every
grant on it, and the role's `information_schema` would describe the physical table again: exactly the
leak spec 026 closed.

**A predicate that now binds and fails is recorded, not thrown.** Refresh covers a whole catalog, and
every read of such an object already fails with the binder's own message; aborting would take the
other objects' verdicts down with it for no gain.

## Enforcement & security

- **Fail closed on the unknown.** An unjudged predicate is treated as untrustworthy exactly where its
  meaning could change — never anywhere else, so the refusal cannot be traded for a lost read.
- **Nothing became readable.** The flag only ever removes trust; a `true` verdict is written by the
  same probe that already ran.
- **The verdict is operator-visible** on `acl_relations()`, `acl_grants()` and `acl_object_grants()`,
  so "which of my grants was never checked" is a query rather than a guess.
- **A refresh is a privileged operation** already: it binds against physical objects, and it is
  reached through `manage`.

## Testing

`test/sql/acl_validation_completeness.test` (81 assertions): a grant written against an unattached
object recorded `false` while one written against a live object records `true` and one without a
predicate records `NULL`; reads and a single-relation write still working under the unjudged
predicate; a `MERGE` and an `UPDATE … FROM` refused by name; `acl_refresh_schema` flipping the verdict
and the same `MERGE` then succeeding; a predicate with no subquery merging unjudged (the refusal is
as narrow as its reason); an object's own predicate carrying the same verdict; a predicate that binds
and fails recorded as `false` without taking the rest of the catalog's refresh down; a grant
projection that could not bind re-probed on refresh, with the role's `information_schema` following
it; a refresh run while that source is detached keeping the rows it probed earlier; and a catalog
grant's predicate judged against every object of its catalog, flipping to `false` when one is added
that it does not fit.

## Alternatives considered

- **Re-check the predicate at query time.** Correct by construction and far too expensive: a bind per
  statement per object, on the hot path, to answer a question that changes only when the physical
  world does.
- **Refuse to write a predicate whose object cannot be bound.** Spec 021 already rejected this: it
  forces an attach order on the operator, and a policy catalog is routinely built before the databases
  it describes are attached.
- **Refuse every subquery predicate on a multi-relation write.** Simpler, and it breaks working
  deployments for a risk that the write-time check already rules out in the common case.
- **Qualify inside the subquery too.** It would make the check unnecessary — and would break every
  legitimate correlated subquery, whose inner names belong to its own FROM.

## Follow-ups

- A refresh reports a count, not a list. An operator learns *which* predicates are unchecked from
  `acl_relations()` / `acl_object_grants()`; returning the failures directly would be friendlier.
- `false` conflates "never judged" with "judged and broken". The two are equally untrustworthy for
  enforcement, and equally worth acting on, but an operator would rather see which.
