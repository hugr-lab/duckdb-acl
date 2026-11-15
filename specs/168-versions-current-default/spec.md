# Spec 168: a grant that states no VERSIONS reads the current version

- **Status**: implemented
- **Date**: 2026-11-16
- **Author**: duckdb-acl
- **Supersedes**: spec 167's default ("unstated = every version")

## Summary

A grant without `VERSIONS` now reads a time-travel table (DuckLake, Iceberg) at its current version only, as
`VERSIONS CURRENT` does. A role reads history only where a grant says `ANY`, `AT (…)` or `BETWEEN … AND …`.

## Problem

Spec 167 kept the old behaviour for an unstated clause: every version. A role granted a catalog to read today's rows
also read every deleted row of every DuckLake table through `AT (VERSION => 1)`, until an operator thought to write
`VERSIONS CURRENT` on each grant. History is data an operator grants, not data a role gets by omission. The owner
(2026-11-16): the default is `CURRENT`; before the release there is no backward compatibility to keep.

## Design

- **Read.** `ReadVersions('')` is `CURRENT`. Only `ANY` is every version.
- **Resolved.** `ApplyGrantVersions` unchanged in its order (the object grant's clause, else the catalog grant's);
  `UniteVersions` reads an unstated clause as `CURRENT`, so an unstated grant and a stated `CURRENT` unite, and `ANY`
  is what wins over a limited role (its result `ANY`, never `''`). The spec 146 audit (`EVERY_VERSION`) counts only
  `ANY` roles as reading every version.
- **A driver and the memory store** state no versions: their roles read the current version.
- **Stored rows are unchanged.** A NULL `versions` stays NULL (not stated) - `platform.grants` shows NULL, read as
  `CURRENT`. No schema step: the meaning of NULL changed, not the table.
- **Several roles.** An unstated grant is `CURRENT` where roles unite: beside a stated `CURRENT` it differs from
  nothing; beside a role's `AT` / `BETWEEN` on the same object the limits differ and the read is refused, current rows
  included (spec 167's rule; before, the unstated role read every version and won). The principal reads under one
  role, or the operator states `ANY` where the union should read every version.

## Enforcement & security

Fail closed by default: an `AT` through the virtual catalog needs a grant that admits history. Views refused every `AT`
already. `ACL NATIVE` and the operator read as before (not rewritten).

## Testing

`test/sql/acl_versioned_tables.test`: an unstated grant reads the current rows and refuses `AT` (also through a live
alias); an unstated and a stated `CURRENT` unite; the every-version cases now state `ANY`; a re-grant without `VERSIONS`
is `CURRENT` again. `test/cpp/test_acl_params_passthrough.cpp` `versions-at-parameter` states `ANY` for its in-place
roles.

## Alternatives considered

- **Keep every version, offer a node setting.** A setting is one more thing for an operator to get right, and the
  owner has decided the default.
- **Rewrite stored NULLs to `CURRENT`.** Nothing to rewrite: NULL already reads as `CURRENT`.
