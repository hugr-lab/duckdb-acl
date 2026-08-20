# Spec 005: integration environment, real-database scenarios, CI/CD

- **Status**: implemented
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

Three related things, layout after `hugr-lab/mssql-extension`: (1) a dockerized test environment
with real databases — SQL Server, PostgreSQL, MySQL — plus DuckLake on the PostgreSQL catalog;
(2) integration scenarios that enforce ACL over those live sources through the scanners; (3) our own
CI/CD workflows (checks on PRs, representative builds + integration tests on merges to main and
manual runs, full platform builds on release), replacing the shared distribution pipeline that had
been red since the repo was created.

## Problem

All enforcement was proven against `:memory:` ATTACHes only. The deployment target is a gateway over
*external* sources (PostgreSQL/MySQL/SQL Server/DuckLake), where RENAME-writability, RLS/masking over
scanner-backed relations, and reader-function gating actually matter. Separately, CI was broken: the
shared `_extension_distribution` workflow builds `make release` inside a docker container and runs
`make test_release` on the host — spec 002's `test-cpp: release` prerequisite re-triggered cmake
against the container-made cache (`/duckdb_build_dir` vs the host checkout) and every run failed.

## Design

- **Environment** (`docker/docker-compose.yml`, `.env.example` → `.env`, `docker/init/*.sql`):
  current majors — postgres:18 and mysql:9 initialize themselves from `/docker-entrypoint-initdb.d`;
  SQL Server 2025 gets an init container (the mssql-extension pattern). One fixture shape everywhere, mirroring
  `test/sql/acl.test`: `orders` (tenant-scoped), `employees` (maskable columns), `audit_log` (DML
  scratch). PostgreSQL also carries a separate `ducklake_catalog` database — DuckLake is not a
  server; scenarios attach it with that catalog and a per-run `DATA_PATH` (`OVERRIDE_DATA_PATH TRUE`,
  since the catalog persists the path). Non-clashing host ports 6432/6433/6434. Makefile:
  `docker-up` / `docker-down` / `docker-status`.
- **Scanners** (`extension_config.cmake`): opt-in via `ACL_INTEGRATION=1` so regular builds stay
  lean. Pins come from the duckdb submodule's own `.github/config/extensions/*.cmake` — the versions
  and patches tested against the exact duckdb commit we track. `postgres_scanner` and `ducklake`
  build; `mysql_scanner` is disabled at the submodule pin ("patches do not apply") and flips on here
  the moment the submodule re-enables it. macOS build deps via Homebrew (`libpq`, `croaring`), wired
  into `EXT_FLAGS` by the Makefile; Linux uses `libpq-dev` + CRoaring built from source.
- **Scenarios** (`test/sql/integration/*.test`, run by `make test-integration`, which composes the
  DSNs from `.env` and passes them via `require-env`): per source — RLS with baked claims and column
  masking over scanner-backed relations, writable RENAME with DML end-to-end into the source,
  physical-name and reader-function (`postgres_query`/`postgres_scan`/`mysql_query`) denial with the
  source attached; plus a cross-source scenario (one principal, virtual names spanning PostgreSQL and
  DuckLake: cross-source join, `INSERT` into postgres selecting from the lake). Each file skips
  itself when its scanner or DSN is absent (`require` / `require-env`), so the suite degrades
  gracefully — the MySQL scenario is written and waiting on the pin.
- **CI/CD** (mssql-extension shape, minus its vcpkg machinery — we have no library dependencies):
  - `ci.yml`: `lint` (clang-format `--dry-run --Werror`) and `build-test-linux` on every PR and merge
    to main — an `ACL_INTEGRATION=1` build with postgres/mysql **service containers** sharing the
    `docker/init/*.sql` schemas, running the unit suites *and* the integration scenarios; a
    representative `osx_arm64` build+unit job on merges/manual runs. ccache keyed on the submodule.
  - `release.yml` on `v*` tags and manual runs: the mssql-extension platform set plus wasm —
    linux_amd64, linux_arm64, osx_arm64, windows_amd64 (MSVC, mirroring the ci-tools cmake
    invocation), wasm_mvp/wasm_eh/wasm_threads (emsdk + the ci-tools targets). On a tag the artifacts
    attach to the GitHub release.
  - The red pipeline's root cause is fixed at the source: `test-cpp` no longer depends on `release`;
    it guards on the built archives instead (the mssql-extension pattern) and says how to build.
  - SQL Server CI service is deliberately deferred with its scenarios (below) — the local compose
    carries it already.

## Enforcement & security

The scenarios pin the enforcement story where it will actually run: a granted virtual name is the
*only* path into an attached source — direct physical names (`pg.public.orders`) are denied, reader
functions stay denied even with credentials attached in the session, RLS claims are baked constants
over scanner scans, and write capability flows only through RENAME grants into the real database.
Database credentials live in `.env` (gitignored; `.env.example` carries dev defaults) and in CI-local
service definitions — no secrets in the repo.

## Testing

- `make docker-up && make test-integration` — 61 assertions in 3 scenarios (postgres, ducklake,
  cross-source); the mysql scenario skips until the pin re-enables the scanner.
- Unit suites unchanged and green: `test/sql/acl.test` (134), `make test-cpp` (28).
- CI runs all of the above on every PR; verified locally including a clean `docker compose down -v`
  recreate (SQL Server under ARM64 emulation needs a clean first boot for the sa password to apply).

## Alternatives considered

- **Keep the shared `_extension_distribution` workflow** — opaque (this repo's failures required
  digging through container/host path mismatches), skipped most platforms silently, and has no seam
  for docker-backed integration tests. Own workflows are more YAML but every step is visible; without
  vcpkg they stay a fraction of mssql-extension's size.
- **A SQL Server scanner now** — no scanner builds against the duckdb `main` commit we track:
  `hugr-lab/mssql-extension` targets stable releases (a loadable built against another version does
  not load), and duckdb ships no mssql scanner. The container, its init schema, and the fixture shape
  are in place; scenarios follow when the versions align (or when we re-pin to a stable tag).
- **Community-repo binaries for the scanners** — prebuilt for released duckdb versions only; useless
  against `main`. Building from the submodule's pins is the only version-safe source.
- **Always-on scanners in `extension_config.cmake`** — penalizes every dev/release build with
  scanner compile time and platform deps; the env-gate keeps the default path lean.

## Follow-ups

- SQL Server scenarios + CI service once a scanner aligns with our duckdb pin (env is ready).
- Flip `MYSQL_SCANNER_ENABLED` when the submodule pin re-enables it (scenario already written).
- Wire the gateway repo's e2e suite onto this same compose environment.
