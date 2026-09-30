# Spec 091: re-pin duckdb to a2af0a7 - linking is opt-in

- **Status**: implemented
- **Date**: 2026-09-30
- **Asked by**: the tresor session. tresor, duckdb-acl and acl-otel must sit on one duckdb commit,
  and tresor moves to the head of `v2.0-cyanoptera`. PR #167's distribution run (which builds the
  branch head) had also failed on osx_arm64: `LOAD acl: Extension ... not found` in the C++ tests.

## Problem

duckdb 96063b9 → a2af0a7 (5 commits). One of them, #26189, flips extension linking:

- an extension is linked into duckdb only when a config names it with
  `duckdb_extension_statically_link`;
- `duckdb_extension_load(... DONT_LINK)` is now a FATAL_ERROR.

We relied on the old default: acl, icu, ducklake, httpfs, json and autocomplete were linked, and
postgres_scanner, mysql_scanner, quack and mssql stayed loadable through DONT_LINK. At the new head
acl is built but not linked, so every test that expects acl in the process fails.

## Design

`extension_config.cmake` states the same layout in the new form:

- `duckdb_extension_statically_link(acl)`, `(icu)`, `(ducklake)` in the integration block, and
  `(json autocomplete httpfs)` in the quack block;
- the `DONT_LINK` words on mssql and quack are dropped. Not being named is what keeps them
  loadable, which is what quack needs: the client and the embed must not meet in one static link,
  spec 063.

The quack pin (974927a) and the embed are unchanged; `sync.py` regenerates identical files.

## Testing

The whole gate at a2af0a7 passes:

- `test/sql/*`: 75 files, 5434 assertions
- test-cpp: 17/17
- harness
- test-flight
- test-e2e
- test-integration: 382 assertions

acl-otel moves to the same commit (its spec 014).
