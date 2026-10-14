# Spec 128: re-pin duckdb to f702a1f - statements that expand into several

- **Status**: implemented
- **Date**: 2026-10-14
- **Author**: the agent, at the owner's ask ("да давай перепин")

## Problem

The pin is bba7360 (spec 123). The head of `v2.0-cyanoptera` is f702a1f, 226 commits later, and the distribution
build compiles that head: on 2026-10-14 it broke - hugr-node's first distribution, then duckdb-acl's own would have -
on the Flight door: duckdb #27108 "[async results] Run a statement that expands into several as one query" changed
`StreamsByDefault(written type, StatementProperties, …)` to take the result.

## Design

- **duckdb bba7360 → f702a1f** (the head on 2026-10-14). The extensions come with it: httpfs → abdd053,
  postgres_scanner → 57f857e and mysql_scanner → 66ad12c (their patches are upstream now, none applied); ducklake
  unchanged (one more patch, for musl); quack 974927a unchanged with its patches - `sync.py` regenerates nothing.
  mssql-extension stays at its spec 124 commit unless it fails to build.
- **duckdb #27108, what it changes for us**: a statement the engine expands into several - a dynamic PIVOT, an
  `ALTER … ADD COLUMN` with a volatile default, NOT NULL or UNIQUE, `IMPORT DATABASE`, `PRAGMA copy_database` - now
  runs as ONE submitted query (one transaction, one result), and `Prepare` accepts it with its metadata deferred:
  `MetadataAvailable()` is false, the types are a placeholder (`unknown`, UNKNOWN) and the properties are the
  defaults - a read-only query, whatever the statement does.
  - **The Flight door** decides before a statement runs whether it streams (Submit) or runs to completion
    (Execute). `StreamsAtDoor` keeps duckdb's rule on two forms: on a result, duckdb's own `StreamsByDefault(written,
    result, false)`; on a prepared statement, the same rule with the written type judged first and a statement
    without metadata never streaming - so the placeholder's "read-only" properties never make such a statement
    stream, nor be submitted for its schema.
  - **It runs at GetFlightInfo** (`Expands`: no metadata with every parameter bound), as a count does (spec 111):
    executed under the caller's statement lock, its result kept on the reservation, the schema announced its
    result's - for an ad hoc statement and for a prepared one (whose CreatePreparedStatement can announce only the
    placeholder). Until this pin `Prepare` refused it, and the door answered duckdb's refusal.
  - The rewriter is unchanged: the parser still hands the override a dynamic PIVOT as the `MultiStatement` spec 075
    admits (each enum query rewritten as a read); the parser's split of a script is no expansion any more.
- **duckdb #26958 "Support INSERT, UPDATE, DELETE and MERGE INTO in EXPLAIN (SQL)"**: the SQL a write's optimized
  plan reconstructs - physical names, the injected predicate - is a plan like any other: the explicit `explain`
  capability gates it (spec 052), and the inner write is the rewritten one.

acl-otel, tresor and hugr-node pin the same duckdb and follow the same day.

## Testing

- `test/sql/acl_show_surface.test`: `EXPLAIN (SQL)` of an `INSERT` refused without `explain`; with it, the
  reconstructed SQL names the physical target, and nothing is written.
- `test/e2e/flight/run.sh`: the implicit PIVOT, which the door used to answer with duckdb's refusal, answers the
  principal's slice - the tenant it may see, no column for the one it may not (the enum domain is confined too).
- The whole gate at the new pin: `test/sql/*`, test-cpp, harness, test-integration, test-flight, test-e2e,
  schema-check, clang-format, the fold and thread_local lints; the distribution build dispatched on the PR.

## As built

- **The pin**: duckdb f702a1f. httpfs abdd053, postgres_scanner 57f857e and mysql_scanner 66ad12c (no patches);
  ducklake 80e6155 with duckdb's patches; quack unchanged.
- **The Flight door** (as designed): `StreamsAtDoor` on a result (duckdb's `StreamsByDefault`) and on a prepared
  statement (the rule, the written type first, no metadata never streams); `Expands` runs such a statement at
  GetFlightInfo, the schema its result's (ad hoc and prepared). The schema probe of a statement with an unresolved
  parameter (spec 112) goes through the same `StreamsAtDoor`, so an expanding statement is never submitted for it.
  `ExpandsIntoSeveral` is `!MetadataAvailable()` WITH every parameter bound: duckdb's `MetadataAvailable()` is false
  for an ordinary SELECT whose parameter type the prepare left unresolved too, and the first draft (the review's
  catch) neither streamed such a SELECT nor probed its schema. `adbc_client.py` pins it: `SELECT ? AS v` bound with
  7 is announced (FlightInfo, `adbc_execute_partitions`) with an integer column - it fails with the draft's test.
  `test/e2e/flight/run.sh`: `PIVOT (SELECT tenant FROM orders) ON tenant USING count(*)` answers `{'acme': [5]}` and
  names no other tenant.
- **`EXPLAIN (SQL)` of a write** (`acl_show_surface.test`): refused without `explain`; with it the answer is the
  rewritten write - `INSERT INTO phys.lake.events …` (and, under a grant's predicate, the write-check of spec 024) -
  and nothing is written.
- **DuckLake on PostgreSQL was broken upstream**: duckdb-postgres renamed `pg_clear_cache` to `postgres_clear_cache`
  (98ee7fc) and removed `postgres_attach` / `postgres_scan` (16737d4), while ducklake - its pin 80e6155 and its main -
  still runs `CALL pg_clear_cache()` in its postgres metadata manager: every DuckLake-on-PostgreSQL scenario failed
  ("Failed to clear the PostgreSQL metadata cache"). The owner chose to carry the one-line fix
  (`patches/ducklake/9001-postgres-clear-cache-renamed.patch`): `extension_config.cmake` declares ducklake's content
  itself (the first declare wins over register_external_extension's) with the submodule's pin, read from its config,
  and one patch directory - duckdb's ducklake patches and ours copied together, since duckdb's script applies one
  directory and refuses a tree it already changed. Only the test build carries ducklake. Our own
  `acl_quoted_names_postgres.test` calls the new name. (`postgres_scan` stays a member of the seeded `readers`
  category: a member with its kind written may name a function the node lacks.)
- **The CLI's agent mode**: in an agent's shell (`AI_AGENT`, `CLAUDECODE`, … - duckdb's shell lists the markers)
  the CLI prints its agent layout; at this pin the Flight door's last check and the door e2e's probes no longer
  matched it (the legs skipped themselves). The Makefile `unexport`s the markers for every recipe; CI sets none.
- A stale FetchContent clone of a scanner whose patches were dropped trips the git-update stash: wipe
  `build/*/_deps/<ext>_extension_fc-*` (CI is fresh).
- Gate (macOS, with mssql): the build, `test/sql/*` (103 files, 9389 assertions), test-cpp, test-integration
  (17 files - postgres, mysql, ducklake, mssql), test-flight (8 scripts), test-e2e (postgres, mssql, ducklake, pair;
  types), harness, clang-format, the fold and thread_local lints, schema-check. mssql-extension 3645903 (spec 124)
  builds at this pin: not re-pinned.
