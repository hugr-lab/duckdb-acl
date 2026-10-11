# Spec 121: a tool's tree within budget

- **Status**: accepted (owner, 2026-10-11 - the plan below; numbers to be met, measured before and after)
- **Date**: 2026-10-11
- **Author**: duckdb-acl
- **Builds on**: spec 119 (metadata at scale - the narrowing, the per-source reader), 115 (metadata for tools);
  acl-clients spec 006 (the JDBC driver's listings) and 007 (the DBeaver plugin)

## Summary

Expanding one node of a tool's tree - a catalog's schemas, a schema's tables, a table's columns, keys or references
- costs **250-500 ms end to end** (owner, 2026-10-11) at the target scale (spec 119: 100-200 sources, one shared
virtual catalog; ≥10k schemas, ≥100k objects), whether the sources are duckdb files or behind the postgres / SQL
Server scanners and whether the policy catalog is a duckdb file or postgres. 270 ms per listing is acceptable; what
is not is a listing the size of the node instead of the expansion, or several listings per expansion.

## Problem

Measured 2026-10-11 (`test/bench/metadata_scale.py`, 200 sources x 150 tables x 10 columns = 30,000 tables, warm
median in one CLI process, seconds; the `jdbc …` rows are the exact SQL acl-clients' driver sends per expansion):

| expansion | duckdb sources | postgres sources | SQL Server sources | policy in postgres |
| --- | --- | --- | --- | --- |
| a catalog's schemas (`jdbc getSchemas`) | 0.036 | 0.036 | 0.039 | 0.042 |
| a schema's tables, as the driver asks (`duckdb_tables` ∪ `duckdb_views`) | **0.767** | **0.836** | **0.806** | **0.836** |
| a schema's tables, `information_schema.tables` | 0.047 | 0.047 | 0.048 | 0.052 |
| a table's columns (`duckdb_columns`) | 0.233 | 0.239 | 0.233 | 0.243 |
| a table's keys (`acl_keys()`) | **0.509** | **0.583** | **0.566** | **0.530** |
| a table's references (`acl_references()` ⋈ `acl_keys()`) | **0.835** | **0.862** | **0.838** | **1.369** |
| a schema's functions (`duckdb_functions`) | 0.032 | 0.035 | 0.035 | 0.038 |

- **The tree is already loaded level by level**: DBeaver asks one listing per expansion (the References folder three);
  the size of the rest of the catalog does not move the numbers - spec 119's narrowing holds on every backend.
- **Three listings are over budget on their own**: `duckdb_tables` / `duckdb_views` (≈0.3 s each where
  `information_schema.tables` answers the same in 0.05 s), `acl_keys()` and `acl_references()` - table functions
  that compute every key / reference of every catalog and are filtered after.
- **A table's columns cost ≈0.2 s whatever they are**: the plan cost of the columns surface (spec 119: 19 CTEs, 42
  joins) - inside the budget alone, not twice.
- **Through Flight a statement costs about twice** the CLI's (the dev node: a schema's tables 1.42 s first, 0.70 s
  repeated; columns 0.46 / 0.22): the door prepares, then executes, and duckdb plans again at execution (step 3).
- **A scanner's first touch** (a new process, or the scanner's cache dropped): postgres +0.7-1.0 s, SQL Server
  +5-6 s (mssql-extension loads its catalog whole); later expansions are warm. Shown here, not changed (below).

## Design (in steps; each measured before and after, the numbers recorded in As built)

1. **The driver asks for a schema's tables through `information_schema.tables`** (acl-clients spec 006 addendum):
   `TABLE_TYPE` ('BASE TABLE' / 'VIEW' / 'LOCAL TEMPORARY') and `TABLE_COMMENT` carry what the `duckdb_tables` ∪
   `duckdb_views` form read (`is_view`, `temporary`, `comment`). The References folder asks one listing.
2. **`acl_keys()` / `acl_references()` read only what they are asked about**: the WHERE above them (vcat, object,
   from_object / to_object) narrows them the way spec 119's `ListingScope` narrows the surfaces - before the policy
   tables are read, the WHERE kept as written (a narrowing only removes rows it removes anyway).
3. **One plan for a door's own statement** (owner, 2026-10-11): at our pin the optimizer marks every prepared
   statement that reads a data source `always_require_rebind` ("optimizers can embed the current database state in
   the executable plan", `optimizer.cpp`), so `Execute` after `Prepare` binds and optimizes again - and every
   statement under a principal reads the policy store (measured: `rebind=1`, `Execute` ≈ `Prepare`; `SELECT 42` or an
   unprefixed `duckdb_tables()` reads none and does not). The Flight door prepares at GetFlightInfo /
   CreatePreparedStatement (for the schema and an early refusal) and executes at DoGet - two plans for what is not a
   prepared statement in the classic sense (Arrow's JDBC driver sends even `executeQuery` that way). So **the door, and
   only the door**, takes the flag off its own statement's data (`ClientData::Get(context).prepared_statements[name]`
   on the session's connection) for the **first execution** of a **read-only** statement that comes **within a short
   window** of its prepare (seconds); a re-execution (a client reusing its prepared statement) and a late first one
   rebind as duckdb wants. Nothing global changes: the CLI, the gateway path, the quack door and a user's `PREPARE`
   keep duckdb's behaviour. Safe for the ACL: the rewrite and the decision happen before the plan, and the reservation
   is the principal's and the mode's (spec 047, 120.3).
4. **The columns surface's plan cost**: fewer CTEs / joins on the one-table path (the narrowed keys are known
   before the SQL is built).
5. **`duckdb_tables` / `duckdb_views` as cheap as `information_schema.tables`** for other tools that ask that way
   (the same narrowing and physical reads).

The budget is a test: the bench's `jdbc …` rows ≤ 0.25 s on the node at 200 x 150 for every backend column above,
and one end-to-end run through the door and the driver (≤ 0.5 s per expansion, first text). A scanner's first touch
is reported by the bench (the `first` column), not budgeted: it is the scanner's catalog load (warming the sources at
the node's start is a possible follow-up, the owner's call).

## Enforcement & security

Nothing is decided anew: a narrowing chooses which policy rows and physical sources are read; every row still goes
through the principal's grant filters, and the WHERE stays as written. A form the narrowing does not understand
narrows nothing (slower, never wider). The driver's listing change reads a surface the principal reads already.

## Testing

- `test/bench/metadata_scale.py` (`--sources-in duckdb|postgres|mssql`, `--policy-in duckdb|postgres`): the table
  above, before and after; the `jdbc …` rows are the driver's SQL.
- sqllogictests for each narrowing (keys / references by vcat and object: the same rows as without it, other
  catalogs' rows never read - a probe that fails if the whole set is computed), the Flight single plan (a counter or
  the profile), and the driver's new tables listing (acl-clients' unit + live tests; the plugin's LiveExpansionTest
  records each expansion's listings and their time).

## Alternatives considered

- **A per-node metadata cache** (spec 119's follow-up): the right answer for an unfiltered listing over 200 sources,
  not for an expansion - an expansion is already narrow; a cache would hide the plan cost, not remove it.
- **Prefetching in the plugin**: more listings per expansion, the opposite of the goal.

## Follow-ups

- Warming the scanners' catalogs at the node's start (SQL Server's first touch is seconds).
