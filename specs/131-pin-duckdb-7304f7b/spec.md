# Spec 131: re-pin duckdb to 7304f7b, the scanners to their mains

- **Status**: implemented
- **Date**: 2026-10-15
- **Author**: the agent, at the owner's ask ("и можно сразу поднять пин mssql", "и бамп duckdb", "и ducklake и
  postgres")

## Problem

The pin is f702a1f (spec 128). The head of `v2.0-cyanoptera` is 7304f7b, 554 commits later, and the distribution build
compiles that head. The scanners moved on their own mains the same day:

- mssql-extension main (7c75db2) builds against duckdb bde1b27;
- ducklake main (4e923e2) builds against duckdb bde1b27 and calls `postgres_clear_cache` itself, so spec 128's patch
  is no longer needed;
- duckdb-postgres main (ed73241) is five commits past the branch's pin 9671d2c, on the same duckdb.

## Design

- **duckdb f702a1f → 7304f7b**, the head on 2026-10-15. It brings httpfs abdd053 (one more patch), mysql_scanner
  e130b41 and quack 974927a with its patches, unchanged, so `sync.py` regenerates nothing.
- **postgres_scanner**: a load of ours at duckdb-postgres main ed73241 instead of the submodule's include (9671d2c).
  duckdb carries no patch for it.
- **ducklake**: a load of ours at ducklake main 4e923e2, with no patch. The submodule still pins 80e6155 and patches it
  (0017-0020); main already carries what those patches add. Spec 128's `patches/ducklake/9001` and the
  FetchContent_Declare that applied it are removed.
- **mssql-extension**: 3645903 → 7c75db2.

acl-otel, tresor and hugr-node pin the same duckdb and follow the same day.

## Testing

The whole gate at the new pin:

- `test/sql/*`, test-cpp, harness;
- test-integration, test-flight, test-e2e (the door legs: postgres, mssql, ducklake and the pair);
- schema-check, clang-format, the fold and thread_local lints;
- the distribution build, dispatched on the PR.

## As built

- **No code change.** duckdb 7304f7b builds the extension and its tests as they are: no API drift reached acl in
  554 commits. The scanners build at their mains, with mssql at 7c75db2.
- **ducklake on PostgreSQL** works without a patch of ours: the door's ducklake leg and the postgres x ducklake pair
  pass. `patches/ducklake/` and the FetchContent_Declare that applied it are gone.
- **duckdb #27257** redacts `extra_http_headers` in how an http secret is shown. Our one use sends them: a client's
  lineage headers to the quack door (`acl_lineage_quack.test`). That test passes, because httpfs still sends the
  values. tresor's session found two tests of its own that read a value back.
- **Found while bumping**: duckdb's grammar-extension API has been in our pins since eb0d9df. Spec 132 takes it up.
- **The gate**, all green:
  - `test/sql/*`: 9563 assertions in 104 test cases;
  - test-cpp: 26;
  - test-flight: 7 scripts;
  - test-e2e: postgres, mssql, ducklake and the pair, plus types;
  - test-integration: 539 assertions;
  - harness, schema-check, the thread_local and fold lints.
