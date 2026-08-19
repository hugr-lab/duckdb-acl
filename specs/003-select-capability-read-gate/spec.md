# Spec 003: the 'select' capability gates the read path

- **Status**: implemented
- **Date**: 2026-08-19
- **Author**: hugr-lab

## Summary

Enforce the `select` capability on the read path. Before this fix, `TablePolicy.caps` was consulted
only by `ResolveDmlTarget` (the DML path), so a grant that deliberately withheld `select` — a
write-only audit/ingest table — still leaked full read access through both replacement forms. Found
by the spec 002 PR review.

## Problem

`acl_grant_table('r', 'audit_log', 'phys...', '', '', 'insert')` was intended as write-only, but
`ACL ROLE "r" SELECT * FROM audit_log` returned the physical rows: `RewriteTableRef` resolved the
policy and applied RENAME/SUBQUERY without ever looking at `caps`. The hole was invisible to the
whole suite because every existing grant included `select`, and `AclGrantTableFunc` even defaults an
empty caps list to `{"select"}`.

## Design

- **Resolution / rewrite** — `RewriteTableRef` (BASE_TABLE branch) checks `policy.caps` for `select`
  right after `ResolveTable`, before either replacement form is applied. The denial mirrors the DML
  message: `select on "<name>" is not allowed`. Every read position routes through `RewriteTableRef`
  (subqueries, `EXISTS`/`IN`, CTE bodies, `INSERT … SELECT` sources, DML `FROM`/`USING`), so one gate
  covers them all.
- **Scope** — relations (tables/views) only. View grants (`acl_grant_view`) and vfunc grants always
  insert `select` into `caps`, so they pass. Function-alias policies carry no caps and are not read
  in this gate; functions stay gated by the `FunctionAllowed` seam.
- **Defaults unchanged** — a NULL/empty caps argument to `acl_grant_table` still defaults to
  `{"select"}`; only an explicit caps list that omits `select` becomes write-only.

## Enforcement & security

The denial happens at parse time before bind, at the same fail-closed point as an unknown name, so a
write-only object cannot be read anywhere in a statement — including from inside the statement that
legitimately writes it (`INSERT INTO audit_log SELECT … FROM audit_log` is refused). DML capability
checks are untouched (`ResolveDmlTarget` still requires the per-verb capability and RENAME form).

## Testing

`test/sql/acl.test` (spec 003 block): a write-only grant is denied on direct `SELECT`, inside an
`EXISTS` subquery of an otherwise-allowed query, and as an `INSERT … SELECT` source, while its
`INSERT … VALUES` still lands in the physical table.

## Alternatives considered

- **Gate only in `BuildTableSubquery`** — misses RENAME-form reads entirely.
- **Treat empty caps as deny-all** — breaks the existing NULL-caps → `select` default and every
  registered policy.

## Follow-ups

- A `select`-like capability story for virtual table functions (today they are always readable once
  granted); revisit with the production role-aware resolver.
