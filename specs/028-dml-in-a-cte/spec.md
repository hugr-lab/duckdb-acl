# Spec 028: a DML statement inside a `WITH`

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

DuckDB lets a CTE body be an `INSERT`/`UPDATE`/`DELETE`, and lets a CTE be the source of one. Every
policy that applies to a top-level write already applies inside a `WITH` — the walk reaches both
positions. This spec adds the coverage that proves it and pins the two shapes DuckDB does not allow,
so we notice when it starts allowing them. **No behaviour changed.**

## Problem

The rewriter walks query nodes generically, so a DML node under a `WITH` is rewritten like any other.
That was believed correct and never tested. Believed-correct-and-untested is a poor state for a
security surface, and this one is new: data-modifying CTEs arrived with DuckDB 2.0, so nothing in the
suite exercised the shape at all.

Two properties in particular were worth establishing rather than assuming:

- **An unreferenced data-modifying CTE still executes.** `WITH d AS (DELETE … RETURNING id) SELECT 1`
  performs the delete even though nothing selects from `d`. A walk that skipped a CTE nobody reads
  would be a write nobody checked.
- **A CTE may shadow the name of the write target.** In `WITH orders AS (…) INSERT INTO orders …
  SELECT … FROM orders`, the read resolves to the CTE and the write target resolves to the catalog.
  The scope stack that keeps a CTE name from resolving as a catalog object (spec 001) must not also
  keep the *target* from resolving — or the write would go somewhere unchecked.

## Design

Nothing to design: both positions are reached by the existing walk, and every gate is where it
already was. What this spec records is which properties are now held down by tests, and which of
today's limits are DuckDB's rather than ours.

**DuckDB's own limits, pinned as tripwires.** A data-modifying CTE below the top level
(`SELECT (WITH d AS (DELETE …) …)`) and a `MERGE` as a CTE body are both refused by DuckDB's parser
today. Each would be a new position for the walk to reach, so the tests assert the current refusal:
when DuckDB relaxes either, the suite says so instead of silently gaining an unwalked position.

## Enforcement & security

Verified under a principal, all through the ordinary path:

- the grant's predicate confines what a CTE's `INSERT` writes (spec 024) and what its `UPDATE` /
  `DELETE` reach — a `DELETE` with no `WHERE` of its own still only removes the principal's rows;
- the capability gate applies to a CTE's target, and a physical name is no more reachable there than
  anywhere else;
- `RETURNING` inside a CTE is a read, so a column the grant does not project cannot be returned;
- a read-only target (a view) is refused;
- a CTE *source* of a write is rewritten like any other read, and as the second relation of an
  `UPDATE … FROM` or a `MERGE` it cannot capture the target's predicate (spec 020) — including when
  it carries a column of the same name;
- the write check still fires when a CTE shadows the target's name.

## Testing

`test/sql/acl_dml_in_cte.test` (108 assertions), covering each bullet above plus the two pinned
DuckDB refusals. Every expectation held on the first run — the value here is the tripwire, not a fix.

## Alternatives considered

- **Refuse DML in a CTE outright.** It is ordinary SQL that the gateway's clients will write, and
  refusing it would buy nothing: the same statement split in two is equally allowed and equally
  checked.
- **Leave it untested since it "obviously" works.** The unreferenced-CTE case shows why not: it is
  only obvious once you know a data-modifying CTE runs whether or not anything reads it.

## Follow-ups

- `MERGE` as a CTE body is refused by DuckDB, not by us. If it lands, its actions need the same walk
  the top-level `MERGE` gets — the tripwire test is what will tell us.
