# Spec 146: the role union is per object - documented and audited

- **Status**: implemented
- **Date**: 2026-10-23
- **Author**: hugr lab (found by spec 145's review; the owner, 2026-10-23: document it, write an audit event - "это
  конечно дыра но тогда можно сказать что раз так то будьте аккуратны", the per-cell union too complex for pushdown)

## Summary

A principal holding several roles reads (and writes) under the union of their policies (spec 011) - per object: the
rows OR-ed, the column lists united, independently. Two roles that narrow one object differently therefore unite into
cells neither reads: role A's rows with role B's columns. This spec keeps the model, says so where the operator reads
the rules, and records each such union as an audit event.

## Problem

```sql
GRANT CATALOG c TO ROLE analyst WITH (select) MAIN RLS (tenant = 'acme') COLUMNS (id, amount);
GRANT CATALOG c TO ROLE hr_globex WITH (select) MAIN RLS (tenant = 'globex');
-- a token naming both reads acme's rows WITH salary: neither role does
```

A per-cell union (`CASE WHEN <the predicates of the roles that see c> THEN c END` per column) was considered and set
aside by the owner: its complexity, and a projection the sources' pushdown does not carry.

## Design

- **Detection** (`RoleUnionWidens`, header-only in acl_policy_catalog.hpp, the pair type `UnionWidening` in
  acl_policy.hpp): over the grant rows a capability's policy unites (spec 145), each role's own `RowPolicy`. A's rows
  are read whole by A and by every role whose filter is A's or none (the *readers*); a role B with another filter
  widens them by each item of its list no reader covers - a reader lists it or a column / path above it (spec 102)
  plainly with nothing masked at or under it, or masks that very item too (two masks of one item are refused). A
  reader without a list covers everything; B without a list adds every known column no reader covers (`*` when the
  columns are unknown). Every widening is reported, not the first: one pair per set of rows (a filter, named by the
  first role holding it - the roles sorted by name) and B, at most 16 per event (then "and more").
- **What is known**: the object's columns are its declared list (never spec 099's type facts - those are only the
  columns exposed differently); an item whose column is not in the list is no cell. Without one an item a
  catalog-wide list names that the object lacks is reported too - the node does not look at the source on the query
  path (spec 065). Predicates are compared as written and, when that finds pairs, again as the parser prints them
  (`id=2` = `id = 2`; merging spellings only removes pairs, so the parse is paid only then); a filter that contains
  another is not decidable from text and reports - the event says *may*.
- **Where**: `LookupRelation`, `LookupSchemaAlias` and `ResolveFunction` (table functions) collect `(role, RowPolicy)`
  (`g."role" AS grole` is each resolver select's last column) and call `NoteUnionWidens` AFTER the policy applied (a
  refused resolution reports nothing), roles sorted by name. The object is the canonical name; for a live alias the
  alias itself (`vcat.alias`), never the tail a client wrote. Detection runs where the resolver computes (a cache miss:
  per role set, name as written, capability and node type settings): per set of rows x B x B's items, each against
  that set's readers, the open readers' answers kept per item. Measured on the first query: 50 roles x 400 columns or
  100 x 200 with distinct filters +20-40 ms; 50 open roles listing 200 columns + 50 filtered listing the other 200
  (a real widening) 0.083 s against 0.077 s without the check; none after (cached).
- **The event**: kind `policy`, detail `role_union_widens`, the object with the capability, `reason` = `the union of
  roles a, b may show cells none of them reads: b's columns x, y on a's rows; ...` (cut at the contract's 512 bytes);
  never a value or a predicate's text, no principal (the statement events name who). Level `DENIED` with `allowed =
  true` - a warning recorded whenever anything is (serving.md's levels say so), at the node's level (it is no
  session's). Floored once a minute per object, capability and the roles involved, in its own map (`union_floor`,
  cleared past 4096 - spec 136's floor is not touched), stamped only by a RECORDED event (one dropped at `off` does
  not silence the next minute - spec 136's `source_unreadable` floor had the same order and is fixed alike); counter
  `acl.policy.role_union_widens{capability}` at every resolution that widens.
- **Docs**: security.md states the per-object union, the example, the advice and the limits; serving.md lists the
  event and the levels exception.
- Spec 145's DML rule stays: beside a verb role that may not read, a statement's conditions read only what every verb
  role reads.

## Enforcement & security

- Nothing is refused that was allowed: the model is the owner's. What changes is that the operator can see the union
  it computes - in the ring, the audit file, and through acl-otel.
- The event carries policy names (an object, roles, listed items) - the operator's own vocabulary. A principal cannot
  multiply events: the object of an alias is the alias, roles reach it only through grants on the object, and the
  floor is per role set.
- A union first resolved while auditing is `off` is counted, not recorded, until the policy changes (the resolver's
  cache): turn the audit on, or write the policy, to see it.

## Testing

- sqllogictest `acl_role_union_audit.test`: the same filter on both roles - no event; different filters - the read
  (the widened cells, as documented), one event with the object, the pairs and the counter; a role without a filter -
  no event; two narrowed lists - both pairs named; fields (a whole column covers a path; a field masked under a column
  read whole does not cover it); masks on both sides cover; the same filter spelled twice and a catalog-wide item an
  object with a declared list lacks - no event, an object without one names it; a third role reading both roles' rows
  whole - no event, with its own filter - every pair; a table function; a live alias - one event named by the alias
  whatever tails are written; a role without a filter but with a list widened by another's columns; an ENUM column
  (a type fact) does not stand for the object's columns; turned on after a resolution at `off`, the next one within
  the minute is recorded.

## Alternatives considered

- **Per-cell union**: exact, set aside (above).
- **Refusing the combination** / **intersecting the columns**: would break principals the model admits.
- **Predicting which pairs one token can carry** (the IdP's mappings): out of scope - the audit records the pairs that
  actually meet.
- **Probing the object's columns** to drop items it lacks: the query path never looks at the source (spec 065).

## Follow-ups

- A quoted column item with a dot (`COLUMNS (id, "a.b")`) is stored unquoted and read as a field path (found by this
  spec's review; a spec 102 / 116 defect, its own spec).
