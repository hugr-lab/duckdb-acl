# Spec 123: re-pin duckdb to 664aafa and its scanners

- **Status**: implemented (mssql-extension: see below)
- **Date**: 2026-10-12
- **Author**: the agent, at the owner's ask ("давай поднимем пин duckdb, ducklake и сканеры")

## Problem

The pin was 4fbae43 (spec 104). The head of `v2.0-cyanoptera` is 664aafa, 778 commits later, and the distribution
build compiles that head: on 2026-10-12 it broke on main (`DBConfig::ParseMemoryLimit` now answers an
`optional_idx`). A pin that stays behind tests another duckdb than the one the distribution ships. The SQL Server
scanner is pinned to an mssql-extension commit 208 commits behind its main.

## Design

- **duckdb 4fbae43 → 664aafa** (the head of `v2.0-cyanoptera` on 2026-10-12; no `v2.0.0` tag yet). The extensions
  come with it from the submodule's own `.github/config/extensions/` and patches:
  - ducklake e8924cf → 80e6155;
  - mysql_scanner accd6a7 - built again (it was disabled at the old pin, "patches do not apply"), so our
    `MYSQL_SCANNER_ENABLED OFF` goes and the mysql scenarios run;
  - httpfs → 23b865d; postgres_scanner and quack (974927a) unchanged - `sync.py` regenerates nothing.
- **mssql-extension** was to go 1d74ae2 → ba1b303 (its main); it does not build at 664aafa - see As built.
- **Drift in our sources**: whatever the new API requires, fixed at the call site; listed below as built.

acl-otel and tresor pin the same duckdb and follow the same day.

## Testing

The whole gate at the new pin: `test/sql/*`, test-cpp, harness, test-integration (postgres, mysql, sqlserver,
ducklake), test-e2e (with the mssql legs, now built), schema-check, clang-format, the fold and thread_local lints.
The distribution build is dispatched on the PR.

## As built

- **One drift in our sources**: `DBConfig::ParseMemoryLimit` answers an `optional_idx` (none = unlimited); the
  resource group's `batch_bytes` takes it through an overload of `MemoryLimitBytes` that also takes the old
  `idx_t`, an unlimited answer refused (a batch is a size). Nothing else in `src/` moved.
- **Scanners**: ducklake 80e6155, httpfs 23b865d, postgres unchanged; mysql_scanner builds again, and
  `acl_mysql.test` runs against the docker mysql. quack 974927a: nothing to regenerate.
- **mssql-extension is NOT re-pinned here.** Its main (ba1b303) builds against 4fbae43 and fails at 664aafa: duckdb
  replaced `TableFunction::get_bind_info` (a `BindInfo`) with `get_table_entry` (`optional_ptr<TableCatalogEntry>`),
  the change duckdb patches into every scanner it carries (`0003-table-function-get-table-entry.patch`). Its
  `table_scan.cpp` needs the same; the pin stays at 1d74ae2 (which fails the same way at this duckdb - the mssql
  leg is opt-in, `ACL_INTEGRATION_MSSQL`, never in CI) until mssql-extension moves to this duckdb.
- **Gate** (macOS, 664aafa): `test/sql/*` (106 files), test-cpp, harness, test-integration (postgres, mysql,
  ducklake; mssql skipped), test-e2e (mssql legs skipped), schema-check,
  clang-format, the fold and thread_local lints.
