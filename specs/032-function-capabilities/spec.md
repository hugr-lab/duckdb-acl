# Spec 032: what a capability means for a function

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

Spec 003 left a follow-up open: "a `select`-like capability story for virtual table functions". Spec
012 answered half of it — a call needs `select`, and a call without it is refused. This closes the
other half: the capabilities that *cannot* apply to a function are refused where they are written
instead of being stored and ignored, and the same is done for `manage` on any object grant.

## Problem

Three silent misunderstandings, all of the same shape — a grant accepted something it would never
consult:

```sql
ACL ADMIN GRANT OBJECT c.report TO ROLE r WITH (select, insert, update, delete, merge);
ACL ADMIN GRANT OBJECT c.report TO ROLE r CAPS '{"manage": true}';
ACL ADMIN GRANT TABLE  c.orders TO ROLE r CAPS '{"manage": true}';
```

Each was stored and each did nothing. The first four verbs are never consulted for a function,
because the DML paths resolve relations and a function is not one. `manage` is granted per *catalog*
(spec 009) and read from `role_catalogs` alone, so an object grant carrying it administers nothing —
while an administrator writing it believes they granted administration.

`CatalogGrantSchema` already refused `manage` for exactly this reason. Object grants did not, so the
same mistake was an error at one level and a no-op at another.

A fourth, smaller one: naming a function as a DML target answered `no access to object "report"`,
which is wrong about an object the principal can see and call.

## Design

**`select` is the capability, and the only one.** A call returns rows, so it is a read (spec 012);
that holds for a scalar too, whose value is read the same way. No new capability is invented — an
`execute` distinct from `select` would break every grant that exists and buy nothing, since there is
no second thing one can do with a function.

**A capability that cannot apply is refused where the grant row is written** — in
`CatalogSetObjectCaps`, not in the `CatalogRequireGrantTarget` pre-check. The pre-check is the obvious
place and the wrong one: the legacy wrappers (`acl_grant_table` and friends) register an object and
grant it in one call without passing through it, so a refusal living there is one `SELECT
acl_grant_table(…, 'select,manage')` away from being bypassed. Refused:

- any of `insert` / `update` / `delete` / `merge` when the name is only a function;
- `manage` on any object grant, whichever kind it names.

A capability written as `false` is not a capability and is not refused: `{"select": true,
"insert": false}` is a grant that says `select`.

**What a grant may still do to a function is unchanged.** A table function's rows are narrowed by an
`RLS` predicate and its output by a column list (spec 011); a scalar has neither, and a policy on one
is still refused. Unstated caps still mean "inherit the catalog's" — a refinement never widens by
omission (spec 012), and for a function only `select` is read out of whatever it inherits.

**A DML target that resolves to a function says so.** When the relation lookup fails, the function
resolvers are asked before the refusal is written, so an administrator reads
`"report" is a function, which is called rather than written` instead of `no access`.

## Enforcement & security

- **Nothing became callable.** The change refuses grants; it never accepts one it did not before.
- **The refusals are at write time**, so an existing catalog is unaffected until a grant is rewritten
  — a stored `{"manage": true}` on an object still administers nothing, exactly as before.
- **A misconfiguration that reads as more permission than it is, is the dangerous kind.** An
  administrator who wrote `manage` on an object and moved on believed they had delegated
  administration; the ACL knew better and said nothing.
- The DML message names a *kind*, not a definition, and only for a name the principal already
  resolves — so it tells them nothing they could not learn by calling it.

## Testing

`test/sql/acl_function_capabilities.test` (45 assertions): `select` letting a table function and a
scalar be called and an explicit `{}` taking it away from each; each of the four write verbs refused
on a table function and on a scalar, with the verb named; `false` not counting as a capability; a
relation still taking all five; `manage` refused on a relation grant and on a function grant while
still working at the catalog level; `INSERT`/`UPDATE`/`DELETE` naming a function refused by kind
while a name that is nothing still says so; a grant's `RLS` and column list still narrowing a
table function, with a policy on a scalar still refused; and the legacy `acl_grant_table` wrapper
refused for `manage` too, since it reaches the write without the pre-check.

`acl_function_select_gate.test` demonstrated "an object capability overrides the catalog's downward"
with `CAPS '{"insert": true}'` on a scalar — a grant this spec now refuses. It says the same thing
with `CAPS '{}'`, which is what an administrator would actually write.

## Alternatives considered

- **Invent an `execute` capability for functions.** Cleaner in the abstract and worse in practice: it
  would break every existing grant, and `select` already means "may read what this produces" for
  relations, views and table functions alike.
- **Keep accepting the useless capabilities.** They cost nothing at query time — but a grant is a
  statement of intent, and one the ACL silently ignores is worse than one it refuses.
- **Materialise `select` as the caps of a function grant that states none.** It would make
  `acl_object_grants()` read more truthfully, but it breaks spec 012's rule that an object grant
  stating nothing inherits the catalog's — including the case where the catalog has no `select`.
- **Refuse `manage` at read time instead**, so existing catalogs are cleaned up. A read-time refusal
  turns an old misconfiguration into an outage; refusing the next write reports it without one.

## Follow-ups

- A stored `{"manage": true}` on an object grant written before this spec is still stored and still
  ignored. `acl_object_grants()` shows it; nothing reports it as dead. A validation pass over an
  existing catalog — the shape spec 027 gave predicates — would.
- A table function that a grant narrows to no columns at all is refused only when it is called, with
  the relation's message ("exposes no readable columns"). The grant could be refused where it is
  written, as spec 026 refuses a projection that cannot bind.
