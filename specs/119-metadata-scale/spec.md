# Spec 119: metadata at scale - a listing reads the sources it answers about, not the node

- **Status**: accepted (by the owner 2026-10-11, after the measurements below)
- **Date**: 2026-10-11
- **Author**: Claude (design/079 with the owner)
- **Follows**: spec 010/025/035 (the metadata surfaces), 039 (the broken-list mark), 046 (the Flight catalog
  RPCs), 115, 116, 117, 118.3 (the per-source reader), 070 (refuse, never truncate).

## Summary

The target deployment (owner, 2026-10-11): **100-200 physical sources** attached to a node, each with its own
schemas, tables and views (100-200 objects each), and **one shared virtual catalog** built over them. Expanding
one node of a tool's tree must cost what that node holds - read the one source behind it - not what the whole
node holds. Measured: today every listing walks duckdb's node-wide `information_schema`, so each attached
source taxes every listing of every role. This spec makes the physical reads per source and keeps a row bound
as a safety knob. A per-node metadata cache with a TTL - the path for an unfiltered listing over 200 sources -
is after the release (its behaviour in a cluster is its own question).

## Measurements (2026-10-11, before; scratchpad bench119, to move into `test/bench/metadata_scale.py`)

Warm median, seconds, as a principal (operator's raw `information_schema` in brackets):

| scenario | tables, one schema | columns, one table | Flight GetTables + schema |
| --- | --- | --- | --- |
| 1 table (the floor) | 0.029 | 0.145 | - |
| 2,000 RENAME relations | 0.104 [0.010] | 0.265 [0.026] | 0.53 |
| 100 schema aliases x 100 tables | 0.343 [0.046] | 0.515 [0.122] | 1.05 |
| the same + an unrelated 20k-table source | 0.674 | 0.838 | 1.69 |
| 2,000 relations, policy in postgres | 0.187 | 0.366 | - |

Where it goes:
- **The broken-list mark (`physcols`, spec 039)** walks `information_schema.columns` of the whole node on every
  surface that reads the objects (`duckdb_schemas` included), even when no relation declares a column list:
  ~1.5-1.8 µs per column anywhere on the node - an unrelated 200k-column source adds 0.36 s to every listing.
- **duckdb's own listings do not narrow**: `information_schema.columns` filtered to one schema costs what the
  whole node does (0.24 s at 400k columns); 118.3's per-source reader answers one schema in 0.001 s.
- The rows returned do not drive the cost (2,000 = 1); the policy tables are milliseconds (20-40 ms in postgres);
  the columns surface has a ~0.1 s plan cost of its own (19 CTEs, 42 joins).
- Flight passes its filters as `$n` parameters (`acl_catalog_rpc.cpp`): a narrowing that reads constants never
  sees them.

## Design (in steps; each measured before and after, the numbers recorded here)

### 1. The broken-list mark only where it can matter
`physcols` is computed only on the tables surfaces, only for relations that declare a column list, and only
over those relations' physical tables - through the per-source reader, never `information_schema.columns`.
Expected: most of the cost of every scenario (the 100-alias tables listing ~0.34 → ~0.05 s).

### 2. Physical facts per source
The joins on duckdb's `information_schema.tables / .columns` become the per-source reader (118.3's
`acl_platform_sources.cpp`, generalized: a list of `<db>[.<schema>[.<table>]]`), called with the sources the
**narrowed** objects and aliases name. The narrowing: the rewriter reads, from the WHERE directly above a
substituted surface, the conjuncts on its catalog / schema / name columns with a constant (`=`, `IN`, `LIKE …
ESCAPE`) and narrows the policy CTEs with them before anything physical is read; the WHERE stays as written
(a narrowing only removes rows it removes anyway; an unknown form narrows nothing). The Flight catalog RPCs
write their filters as literals (they compose that SQL themselves) so the narrowing sees them. A source whose
catalog fails is left out - its objects listed without physical facts, never the whole listing failed.
Expected: expanding one schema near the floor (0.03 s tables, 0.15 s columns) whatever else is attached; an
unfiltered listing still reads every source it lists (that is the cache's, later).

### 3. The admin's tree narrowed the same way
`platform.attached` (118.3) reads only the sources the narrowed rows name.

### 4. A row bound - a safety knob, not speed
`acl_metadata_max_rows` (GLOBAL, default 10000, `0` = unlimited; a session may only lower it - spec 068's
allowlist) bounds each substituted surface after the narrowing: above it the statement is **refused** with
`more than N rows of <surface> - narrow by catalog, schema or name` (reason `at_capacity`), never cut. The
Flight RPCs and quack's catalog load (its `duckdb_schemas()` / `duckdb_tables()` / `duckdb_views()` arrive through
the door) fall under it.

### Not here
- **A per-node metadata cache with a TTL** (owner, 2026-10-11): after the release - how a cache on each node of
  a cluster stays coherent is its own design.
- The columns surface's ~0.1 s plan cost: looked at, changed only if a simple form falls out; else recorded.
- A metadata timeout, streamed Flight catalog batches, a per-group bound.

## Enforcement & security

A narrowing never widens (it removes only what the outer WHERE removes; an unknown form narrows nothing); the
per-source reads read physical metadata only of objects the principal already sees; visibility (grants, masks,
platform scopes) is untouched; the bound refuses, never shortens.

## Testing

- `test/bench/metadata_scale.py` (from bench119): the scenarios above plus **200 sources x 150 objects under
  one virtual catalog**, quack's catalog load, an admin holding a data grant; before / after per step here.
- `test/sql/acl_metadata_scale.test`: narrowing forms (`=`, `IN`, `LIKE … ESCAPE` narrow; OR, functions,
  parameters do not - same answers); a failing source left out of an unfiltered listing and absent from a
  filtered one; the mark still marks a broken declared list; the bound (N answered, N + 1 refused, a session
  lowers, cannot raise, `0`); Flight GetTables / GetDbSchemas with filters (e2e); a quack ATTACH above the bound.
- Every existing listing test unchanged.

## Alternatives considered

- **The draft's filter pushdown alone** - measured: the policy CTEs are milliseconds; the cost is the node-wide
  physical scans, which a filter outside them does not reach.
- **Truncate at N** - a tool takes a short answer as complete (spec 070).
- **A metadata cache now** - the real answer for an unfiltered listing over many sources, but a cluster's
  coherence is unsettled; after the release.
