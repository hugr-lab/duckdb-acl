# Spec 019: a write may qualify its columns by the name the principal used

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

The read path swaps a virtual name for its physical target and keeps the virtual name as an alias, so
`SELECT orders.id FROM orders` binds. The write paths swapped the name and kept nothing, so any write
that qualified its own columns failed to bind — and since `MERGE`'s `ON` clause has no other way to
name its target, **every `MERGE` through a renamed object failed**. Writes now keep the name too.

## Problem

`ResolveDmlTarget` replaced the target's qualified name with the physical one and stopped there:

```sql
ACL ROLE "r" DELETE FROM orders WHERE orders.id = 1;
  Binder Error: Referenced table "orders" not found!  Candidate tables: "orders_physical"
```

The same for `INSERT … RETURNING orders.id`, `UPDATE … WHERE orders.id = …` and every `MERGE`. It
only bites when the virtual name differs from the physical table name — which is the normal case for a
virtual catalog, and why it went unnoticed: the tests always wrote unqualified columns or an explicit
alias, both of which work.

It fails closed, at bind, so this was never a leak — but it made DML unusable from any client that
qualifies its columns, and `MERGE` unusable at all.

## Design

**`UPDATE`, `DELETE`, `MERGE`: keep the virtual name as an alias**, exactly as the read path does. A
user's own alias is left alone; only an absent one is filled in.

**`INSERT`: map the qualifier instead.** DuckDB binds an insert target by its table name and ignores an
alias there — `INSERT INTO t AS x … RETURNING x.id` fails in plain DuckDB, with no ACL involved. So an
alias would not help; instead a qualifier the principal wrote (`orders.id`) is rewritten to the
physical table's name, which is what the binder will look for. This is a translation of the name the
principal used into the name the engine ended up with, and it applies only to `INSERT`, since the other
verbs bind under the alias.

Nothing about *which* statements are allowed changes: the same capability checks, injections, column
gating and predicate ANDing run as before, and a narrowed target still refuses `FROM`/`USING`/`MERGE`
(design/007 §1 — the remaining piece of this area).

## Enforcement & security

The alias is a name for the object the principal already resolved, not a second way to reach one: it is
set *after* `ResolveTable` and the capability check, from the key the principal wrote. The physical
name remains unreachable — `UPDATE phys.main.orders_physical …` and a physical relation in `USING` are
refused exactly as before, and both are tested here rather than assumed.

## Testing

`test/sql/acl_dml_qualification.test` (44 assertions): every verb qualified by the virtual name against
an object whose physical table has a different name; unqualified writes and a user-written alias still
working; `MERGE` with `WHEN MATCHED` and `WHEN NOT MATCHED` branches, and with an explicit target
alias; the physical name still refused both as a target and as a `USING` source; a narrowed grant still
refusing `MERGE` and still applying its predicate to a qualified single-relation write.

## Alternatives considered

- **Rewrite the qualifier for every verb** instead of aliasing. Uniform, but it discards the
  principal's alias in the output SQL and makes `ToString()` read in physical names, which matters for
  a view body (spec 018) and for anything a person has to debug. The alias keeps the statement legible.
- **Refuse a qualified reference with a clear message.** Honest, but it makes `MERGE` permanently
  unavailable, which is not a trade worth making for a two-line fix.

## Follow-ups

- `UPDATE … FROM`, `DELETE … USING` and `MERGE` on a *narrowed* target remain refused (design/007 §1).
  This spec is a prerequisite for that work: those forms need qualified references to bind before the
  target's predicate can be qualified by the target's alias.
