# Spec 039: catalog maintenance - the check that finds what drifted, the repair that mends it on purpose

- **Status**: implemented
- **Date**: 2026-09-08 (first draft 2026-08-21)
- **Author**: hugr-lab

## Summary

The source changes under the virtual catalog - a column is dropped or renamed, a table goes, a
view's dependency moves - and nothing on the query path may look (spec 065: no probing, ever). What
is left is the administrator, off the query path: today `ANALYZE VIRTUAL` re-derives stored
schemas and re-judges verdicts (specs 010/027) but *says nothing*, and a declared `COLUMNS` list
that names a vanished column stays dead until somebody guesses why. This spec adds the named
compensating control every drift discussion has pointed at: **`acl_check_catalog([vcat])`**, a
table function that probes every stored fact against the source and reports what no longer holds -
per object, per grant, with the repair each finding wants - and **`acl_repair_relation(vcat,
vname, action[, spec])`**, which applies the repairs a dead declared list needs (`remap` a column
that moved, `drop_missing` a column that is gone) and **never drops a mask silently**: it refuses,
or removes the mask by name when told to. The cheap two-thirds rides along: a listing **marks** a
broken object instead of quietly describing a narrower one nobody can read. Management SQL:
`CHECK VIRTUAL CATALOG`, `REPAIR VIRTUAL TABLE`.

## Problem

The drift matrix (design/BACKLOG.md, probed 2026-08-21; docs/security.md "Accepted risk"):

1. **A declared-list object dies and stays dead.** `c.customers AS phys.main.customers COLUMNS (id
   = pk, ssn = ssn_raw)`; the source drops `ssn_raw`. Every read fails with duckdb's binder error
   naming the physical column (spec 065 probe A - accepted: names, never data, provokable only by
   an already-granted principal). Healing it automatically is wrong: dropping the vanished entry
   would drop whatever protection rode on that name, "the silently skipped protection" spec 038
   refuses; and to a probe a renamed column looks exactly like a dropped one. So the repair is the
   admin's - and there is no procedure for the admin.
2. **The listing disagrees with the read.** `duckdb_columns()` joins the physical columns, so the
   vanished one drops out and the object is described as `id, tenant` - a narrower object that no
   query returns. Spec 065 rejected hiding it ("an admin must be able to see the object to repair
   it") and asked for *marked*.
3. **`ANALYZE VIRTUAL` is mute.** It re-derives a view's schema and re-judges predicates and grant
   projections, recording verdicts (`rls_checked`) that nothing surfaces. A grant's bare `COLUMNS`
   item that no longer matches intersects away (spec 038): the role silently reads less, and
   nobody is told. A mask whose expression no longer binds refuses every read (spec 038), and
   nobody is told which grant.
4. **Some drift has no verdict at all**: a physical table renamed under an alias, a schema alias
   whose path is gone, an expansion whose source gained or lost tables, a reference whose end
   object was dropped from the catalog.

The reverse direction is fine and stays so: a column *added* to a source becomes visible through a
plain alias or a schema alias, which is what "live" means (spec 014). It is a written decision now
(docs/security.md), not a finding.

## Design

**Repair is not automatic, and that is a decision rather than an omission.** The obvious self-heal
- drop the vanished column from the object's list - also drops any mask on that name. That is the
"silently skipped protection" spec 038 refuses; doing it in a background refresh would be the same
failure with less visibility. An admin repairs, having been told what the repair costs.

### `acl_check_catalog([vcat])` - a report, one row per finding

A **table function**, the operator's (denied to a principal like every `acl_*`; under management
it is catalog-scoped: `manage` on that catalog, or unrestricted for the no-argument form, which
walks every catalog). It runs **off the query path** on fresh connections, exactly as
`acl_refresh_schema` probes, and **writes nothing** - a check is a question. Columns:

| column | meaning |
| --- | --- |
| `vcat` | the virtual catalog |
| `kind` | `table`, `view`, `function`, `schema`, `grant`, `reference` |
| `object` | the virtual name (a schema's path; a grant's object, or `*` for a catalog grant) |
| `role` | the grant's role, else NULL |
| `problem` | one of a bounded vocabulary (below) |
| `detail` | our sentence - it may name the *physical* column or path: this is the admin's surface |
| `repair` | the management statement that mends it, ready to paste |

The vocabulary, what each is judged from, and the repair it names:

| problem | judged by | repair |
| --- | --- | --- |
| `source_missing` | the relation's `phys` does not bind (dropped, renamed) | `ALTER VIRTUAL TABLE … SET PHYS` / `DROP VIRTUAL TABLE` |
| `column_missing` | a declared `COLUMNS` entry whose expression no longer binds against the source | `REPAIR VIRTUAL TABLE … REMAP (…)` or `… DROP MISSING COLUMNS` |
| `definition_broken` | a view's SQL, or a macro's template with its declared parameter types, does not bind | `CREATE OR REPLACE VIRTUAL VIEW … AS` / `acl_alter_function` |
| `schema_stale` | a query-defined object's stored (derived) schema differs from what its definition binds to now | `ANALYZE VIRTUAL …` |
| `rls_broken` | a predicate (object or grant) that fails to bind now | `ALTER … SET RLS` |
| `rls_unchecked` | a predicate never judged (spec 027's verdict is false and the object binds now) | `ANALYZE VIRTUAL CATALOG` |
| `grant_column_missing` | a bare item of a grant's `COLUMNS` list matches no column of the object any more | `ALTER GRANT … SET COLUMNS` |
| `mask_broken` | a `name = expr` grant item whose expression does not bind over the object | `ALTER GRANT … SET COLUMNS` |
| `mask_orphaned` | a grant mask names a column the object no longer has: it protects nothing (the `ssn_backup` case of the drift matrix) | `ALTER GRANT … SET COLUMNS` |
| `schema_missing` | a schema alias's physical path has no schema behind it | `ALTER VIRTUAL SCHEMA … SET PHYS` / `DROP VIRTUAL SCHEMA` |
| `expansion_stale` | an expansion's source has tables it did not record (and did not exclude), or records whose source is gone | `ALTER VIRTUAL SCHEMA … REFRESH [PRUNE]` |
| `reference_dangling` | a reference's end object, or a column it names, is not in the catalog - virtual facts only, no probe | `DROP VIRTUAL REFERENCE` |

What the check cannot judge it says in the docs, not in rows: a bare alias (no declared list) has no
contract beyond "binds", so only `source_missing` can be found on it - declaring `COLUMNS` is the
opt-in to `column_missing` (as it is to spec 065's clean refusals); a table function is probed with
its declared parameter types, so a signature the admin never declared is probed with none.

### `acl_repair_relation(vcat, vname, action[, spec])` -> BIGINT

The repairs a dead declared list needs, applied on purpose; returns the entries changed:

- **`remap`**, `spec` = `'ssn = ssn_new, tenant = tenant_id'`: the named entries of the object's
  `COLUMNS` list get the new expressions. Each new expression is **probed to bind** first (an
  entry that does not is refused, the object untouched; a name the list does not have is refused
  too); then the grants' projections on the object are re-probed (spec 026, non-strict - what
  `ANALYZE` does), so the listing describes the mended object.
- **`drop_missing`**: every entry whose expression no longer binds is removed from the list. It
  **refuses** when a grant on the object (object grant, or the catalog grant's list) carries a
  `name = expr` item on a name it is about to drop - the mask would go from "protecting a column"
  to "orphaned" in the same stroke, silently. The refusal names them: `acl admin: "c.customers":
  dropping "ssn" would orphan the mask of role "analyst" (object grant) - REMAP the column, alter
  that grant, or DROP MISSING COLUMNS AND MASKS`. Bare grant items on the dropped name intersect
  away already (spec 038) and need no refusal. Returns the entries dropped; 0 when nothing is
  missing.
- **`drop_missing_and_masks`**: `drop_missing` plus the removal of exactly those grant mask items,
  by name, from the grants that carried them - nothing is orphaned and nothing is silent: the
  count includes them, and each grant's projection is re-probed. The mask protected a column that
  no longer exists; what the admin acknowledges is that a column of that name is gone for good.

All three are `manage` on the catalog (the scope row `acl_refresh_schema` has), write the policy
catalog under the version bump every write takes (spec 034), and so reach every node through the
ordinary reload.

### The listing marks a broken object

For an alias/subquery relation **with a declared list**, the tables surfaces (`information_schema.
tables`, `duckdb_tables()`, `duckdb_views()`, `SHOW`) compute, by a join and never a probe, the
declared entries whose expression is a bare identifier with no row in `information_schema.columns`
of the physical table. When there are any, the object's comment is prefixed:
`acl: broken - declared column(s) ssn no longer exist in the source; ` + the admin's comment (the
virtual names, never the physical). The columns surface is unchanged - the contract as written: an
object listed from its grant or stored projection (spec 026) keeps the vanished column, one listed
from the physical row shows the survivors - and the mark on the object is what says the read will
fail. A quack client that builds its catalog from `duckdb_tables().sql` keeps working; a person
sees the mark; `acl_check_catalog` has the rest.

### Management SQL

```
CHECK VIRTUAL CATALOG <catalog>                                 -> SELECT * FROM acl_check_catalog('<catalog>')
REPAIR VIRTUAL TABLE <catalog>.<name> REMAP (<v> = <expr>, …)   -> acl_repair_relation(c, n, 'remap', '<v> = <expr>, …')
REPAIR VIRTUAL TABLE <catalog>.<name> DROP MISSING COLUMNS      -> acl_repair_relation(c, n, 'drop_missing')
REPAIR VIRTUAL TABLE <catalog>.<name> DROP MISSING COLUMNS AND MASKS -> acl_repair_relation(c, n, 'drop_missing_and_masks')
```

`CHECK` and `REPAIR` join `ANALYZE`/`COMMENT` in the management-form gate (`IsMgmtStart`: the
word after them is `VIRTUAL`). `AuthorizeMgmt` learns the one compiled form that is a table
function in `FROM` (`acl_check_catalog`), judged like a scalar call: its first argument is the
catalog, none means unrestricted.

## Enforcement & security

- **Nothing on the query path changes.** The check and the repair run on the admin's call; the
  listing mark is a join over catalog facts and `information_schema` - the same join the columns
  surface already makes - not a probe. The resolver keeps spec 065's "no probing, anywhere".
- **The report names physical things** (a column, a path) because it is the administrator's, who
  wrote them; it is denied to a principal like every `acl_*` function and, under management,
  scoped to the catalogs the role manages. Audit: a management batch is one `admin` event (spec
  069) - a `CHECK` is recorded as the call it compiles to; a repair also lands as a `policy`
  `written` event from the backend.
- **A repair never widens.** `remap` replaces expressions that are probed to bind; `drop_missing`
  only removes entries that cannot bind - a column nobody could read - and refuses when that would
  orphan a mask; `drop_missing_and_masks` removes the mask items it names and counts them. No
  action touches a grant's bare items, predicates or capabilities.
- **Fail-closed stays.** A dead object refuses every read before and after this spec; the spec adds
  the way to learn why and mend it, not a way around it.

## Testing

`test/sql/acl_catalog_maintenance.test` (memory source, policy catalog in an attached `:memory:`):

- a declared-list table, a bare alias, a view over the table, a scalar and a table macro, a schema
  alias, an expansion, a reference, two roles - one with a mask (`ssn = NULL`) in its object grant,
  one with a bare `COLUMNS` list and an RLS predicate;
- a clean catalog checks empty;
- `ALTER TABLE … DROP COLUMN ssn_raw`: `column_missing` on the table with the repair text,
  `schema_stale` on the view, `grant_column_missing` for the bare item, the mask untouched (the
  declared list still names `ssn`); the listing carries the mark, the columns surface lists the
  survivors, the read fails as before;
- `REPAIR … DROP MISSING COLUMNS` is **refused** naming the role; `REPAIR … REMAP (ssn = ssn_v2)`
  after `ADD COLUMN ssn_v2` mends it: the principal reads again (masked), the mark is gone, the
  check is empty;
- a second drop, then `DROP MISSING COLUMNS AND MASKS`: returns 2 (the entry and the mask), the
  grant no longer lists `ssn`, the check is empty;
- `ALTER TABLE … RENAME TO`: `source_missing` on the alias and on the declared table; `DROP TABLE`
  behind a view: `definition_broken`; a schema alias to a dropped schema: `schema_missing`; an
  expansion's source with a new table: `expansion_stale`; a reference to an object dropped from
  the catalog: `reference_dangling`; a grant predicate over a dropped column: `rls_broken`;
- the SQL forms compile to the same calls; a principal calling either function is denied; a
  catalog-scoped `manage` role checks its own catalog and is refused another.

## Found on the way

- **A mask keeps its role's reads alive.** The resolver folds a grant's `ssn = NULL` into the
  object's projection and never reads `ssn_raw`, so the analyst still gets rows from an object whose
  declared entry is dead; a role whose grant reads the column gets spec 065's binder error. The
  check reports the dead entry either way - it is a fact about the catalog, not about one role.
- **The columns surface keeps the contract, not the survivors.** A declared-list object with a grant
  projection is listed from `grant_columns` (spec 026) - the vanished column included - so "the
  columns surface lists the survivors" holds only for objects listed from the physical row. Either
  way the mark on the object is what says the read fails; the spec text and the docs say so.
- **An expansion keeps its source in `origin`, not `phys_path`** (spec 014's records): the first cut
  of the schema check skipped every expansion.

## Alternatives considered

- **Heal automatically at `ANALYZE`** (drop what no longer binds): rejected by spec 038 - a
  protection removed silently is the failure mode, and a renamed column looks exactly like a
  dropped one to the probe.
- **Hide a broken object from the listings**: rejected by spec 065 - the admin has to see it.
- **List the vanished column with a placeholder type**: a client building DDL from the columns
  surface would build invalid SQL - the spec 035 failure class; the mark goes on the object.
- **A `broken` column on the tables surfaces**: the surfaces are standard shapes (spec 035); the
  comment is the one free-text field every client already renders.
- **Probe at resolution so the error is ours**: ruled out by specs 038/065 - a query per
  resolution, and a cache that goes stale exactly when an alias is meant to be live.
- **Refuse the catalog while anything is broken**: one vanished column would take every object
  down for every role.

## Follow-ups

- Write-time shape inference for views and table functions (backlog): objects that infer a shape at
  save join the declared branch and get `column_missing` findings instead of `schema_stale`.
- A scheduled check whose rows ship as audit events - the collector's side (spec 069's fleet
  view), once somebody has an opinion about noise.
