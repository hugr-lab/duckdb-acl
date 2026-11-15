# Spec 167: the versions of a time-travel table a grant admits

- **Status**: implemented
- **Date**: 2026-11-15
- **Author**: duckdb-acl

## Summary

A table of a catalog that keeps its history (DuckLake, Iceberg) is read at an older version with duckdb's
`AT (VERSION => n)` / `AT (TIMESTAMP => t)`. A grant now says which versions a role reads (`VERSIONS`). The `AT` is
also carried to the source below the grant's policy, where it used to be dropped.

## Problem

The owner's task (2026-11-05, before the platform's release): per role, only the current version, strictly one
snapshot, or a window of dates. Today a principal's `AT (…)` on a virtual table:

- **In the in-place form** (no policy text) passes through as written: any role reads any history, deleted rows
  included.
- **In the subquery forms** (an RLS, a mask, a column list, a rename, a cast) is dropped silently: the role reads the
  current rows whatever it asked for (found by spec 159's review).

## Design

**Syntax.** A clause of the catalog and the object grant (not of a schema grant, which carries capabilities only).
It reuses duckdb's grammar: its `AtClause` rule, and its BETWEEN operands (`OtherOperatorExpression`, so the `AND` is
the window's):

```sql
GRANT CATALOG c TO ROLE r MAIN VERSIONS CURRENT;
GRANT TABLE c.t TO ROLE r VERSIONS ANY;
GRANT TABLE c.t TO ROLE r VERSIONS AT (VERSION => 42);          -- or AT (TIMESTAMP => …)
GRANT TABLE c.t TO ROLE r VERSIONS BETWEEN TIMESTAMP '2026-01-01' AND TIMESTAMP '2026-06-30';
```

**Functions.** `acl_grant_catalog(…, columns, versions)` and `acl_grant_object(…, columns, versions)` take the clause
as text. The old arities stay. Every grant writer replaces the grant whole (an absent clause = not stated). `ALTER
GRANT` and a repair's rewrite keep the stored clause.

**Stored.** In `role_catalogs.versions` and `role_object_caps.versions` (schema v24). `min_reader` is 24: a v23 build
would ignore the column and serve every version. The clause is stored normalized: `CURRENT`, `ANY`,
`AT (VERSION => 42)`, `AT (TIMESTAMP => TIMESTAMPTZ '…')`, `BETWEEN TIMESTAMPTZ '…' AND TIMESTAMPTZ '…'`.

- Each value must be a constant (constants and casts only) and is evaluated where it is written, on the store's
  connection. A version is an integer type (no rounded `1.9`, no `TRUE`, no `'42'`). A timestamp is a finite instant,
  stored in UTC, so the same instant written under two time zones unites. A `TIMESTAMP` without an offset is read in
  the node's zone (UTC on a build without ICU), so an offset is the exact form.
- What the function form's text holds beyond the clause is refused: a node rebuilt of the item and the FROM alone must
  print the same.
- A stored clause is read back only as constants. Anything else refuses the read, since it would be spliced into the
  principal's statement.
- A window whose start is after its end is refused.
- The function form's text is parsed by duckdb's parser (`SELECT 1 FROM __acl_versions <text>` for an `AT`,
  `SELECT NULL <text>` for a `BETWEEN`). Anything more than the clause is refused.
- The stored text is read back the same way (`acl_versions.{hpp,cpp}`).
- A `VERSIONS` on a view or a function is refused: they read what their definition reads, which is the constructor's
  (spec 138).

**Resolved** (`CatalogBackend::ApplyGrantVersions`, after a relation's or a live alias's union of grant rows).

- **Per role:** the object grant's clause, else the catalog grant's, else every version.
- **United** (`UniteVersions`): every version when one role reads every version, else the roles' one clause.
  Different clauses set `TablePolicy::versions_differ`, which refuses the read, as two masks of one column do
  (spec 102). The roles are the rows that hold the capability exercised (spec 145).
- A driver states none.
- **Audited.** When every version wins over a limited role whose slice differs (an `RLS`, columns), the union reads
  that role's slice in history: a `role_union_widens` event (spec 146, `UnionWidening::EVERY_VERSION`), never a
  refusal.
- **The virtual name decides.** A live alias reaching the same physical table takes the alias's grants, not the table
  object's (found by review).

**Rewritten** (`AclRewriter::VersionedAt`, at the read of a virtual table, after its capability is judged):

| limit | the client's `AT` | the source is read at |
| --- | --- | --- |
| every version | as written | the client's `AT`, if any |
| `CURRENT` | refused | no `AT` |
| `AT (…)` | refused | the grant's `AT` |
| `BETWEEN lo AND hi` | `TIMESTAMP` only, a constant | `CASE WHEN v BETWEEN lo AND hi THEN v ELSE error(…) END`; with no `AT` the window's latest, `v = least(get_current_timestamp(), hi)` |

- **The window is checked at bind.** duckdb evaluates an `AT` expression at bind (`Binder::BindAtClause`), so the
  check runs there. `v` is read twice, so it is a constant: never anything that may answer differently.
- **Calls are the system's.** The `error`, `least` and `get_current_timestamp` calls are written `system.main.<name>`
  (spec 163).
- **Where the `AT` lands.** The in-place form keeps it on the swapped reference. The subquery forms put it on the base
  table at the end of the read's FROM chain (`SourceAt`): below the casts' and the grant's subqueries, so the row
  filter and the masks read the version.
- **Views.** A view refuses any `AT`.

**Parameters.** An `AT` read through a policy is also bound alone (spec 159's guard, now with the version). A
parameter has no value there, so such an `AT` must be a constant. In the in-place form, under every version, the
client's `$1` passes through and is rebound per execution, as duckdb does natively.

**Writes** (`RefuseVersionedWrite`). A write reads and writes the current rows. A grant that reads a snapshot or a
window (`AT`, `BETWEEN`) refuses every verb. This is judged on:

- the verb's grant rows;
- the read's, since a write's conditions read under the read policy. Their clause is read outside the read's own
  `try`, so one that does not read back refuses the write (found by review);
- an upsert's `update` rows.

**Listings.** `platform.grants` and `platform.object_grants` gain a `versions` column.

## Enforcement & security

- **Fail closed.** A stored clause that does not read back refuses the read instead of serving every version. Roles
  whose limits differ refuse.
- **Only constants are stored.** A grant's values are constants, so no policy text runs at read beyond a cast of a
  literal.
- **Values in the window are bounded.** A client's value in a window is a constant, so the value checked is the value
  read.
- **Default unchanged.** Unstated means every version, as before. The rule is that nothing that works today is taken
  away automatically: an operator states `CURRENT` where history must not be read.
- **Other version paths.**
  - DuckLake's own functions (`ducklake_snapshots`, `ducklake_table_changes`, …) are in the never set.
  - A scan function that takes a version (`iceberg_scan(…, version => …)`) is in no category by default, so it is
    refused until an operator puts it in one.

## Testing

`test/sql/acl_versioned_tables.test` (DuckLake, three snapshots), which covers:

- **Every version.** The `AT` is carried in place, through a live alias, and below an RLS (it used to read current).
- **`CURRENT`.** A read without `AT` succeeds, an `AT` is refused, and writes succeed.
- **A pinned `AT`.** A read without `AT` reads the snapshot, also under an RLS. Another `AT` is refused, and so are
  `DELETE` / `INSERT` / `UPDATE`.
- **A window.** A read without `AT` reads the window's latest. A timestamp outside the window, a non-constant and a
  `VERSION` are refused. A window before the table has no snapshot.
- **Views and schema grants.** A view refuses an `AT` and a `VERSIONS` grant. A schema grant refuses `VERSIONS`.
- **Two roles** through a token: differing limits are refused, and every version wins.
- **Inheritance.** An object grant's `ANY` overrides the catalog's `CURRENT`. `ALTER GRANT` keeps the clause and a
  re-grant clears it.
- **Writer validation.** A non-constant, an empty window, the clause twice, a subquery, a trailing clause, a broken
  BETWEEN, NULL and an unknown word are refused.

`test/cpp/test_acl_params_passthrough.cpp` `versions-at-parameter` loads the built DuckLake loadable and skips without
it. It checks that:

- the in-place `AT (VERSION => $1)` keeps the client's one parameter and rebinds it per execution;
- an `AT` parameter under an RLS or a window is refused;
- a constant `AT` beside a parameter reads the snapshot below the RLS.

## Alternatives considered

- **`CURRENT` by default.** It fails closed, but it would take today's `AT` away from every role without a word (the
  owner's rule: nothing rolls back automatically).
- **Clamping a value outside the window** (`greatest(lo, least(hi, v))`). It is safe with any `v`, but it reads
  another version than the one asked for without a word.
- **A rolling window (`LAST INTERVAL …`) and a window of version numbers.** They are left out ("не переусложняй"). A
  version number says nothing about its time, so a time window refuses `AT (VERSION => …)`.
- **JSON for the stored clause.** It would be a second format to read. The clause read by duckdb's parser is the
  form's own.

## Follow-ups

- `platform.effective_rights` / `check_grant` do not show the versions.
- `ALTER GRANT … SET VERSIONS`: today a re-grant changes them.
- Iceberg is not exercised here: no Iceberg catalog in the test build.
