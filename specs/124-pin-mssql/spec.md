# Spec 124: re-pin mssql-extension to its bba7360 build

- **Status**: implemented
- **Date**: 2026-10-13

## Problem

Spec 123 moved duckdb to bba7360 but left the SQL Server scanner at 1d74ae2, which does not build there
(`get_bind_info` became `get_table_entry`; `ResultEagerness` is gone). mssql-extension moved to bba7360 itself
(its #459). Its INSERT is atomic through BCP since its spec 062, with TABLOCK on a heap (its spec 057): a BU lock
held for the whole load - the owner keeps that default.

## Design

- **The pin**: mssql-extension 3645903 (its main, #459 merged; one commit past the tested 3502283, comments and
  spec only).
- **The test database reads on row versioning**: `docker/init/sqlserver.sql` turns `READ_COMMITTED_SNAPSHOT` on for
  `acltest`. The door e2e's reader (a count through quack, 30 s timeout) waited behind the writers' BU lock under
  locking READ COMMITTED and timed out; with RCSI it reads the last committed state and never waits. A load stays
  atomic - seen whole after its COMMIT; a killed loader's rows never appear - which is what the e2e asserts.
- **TLS**: mssql-extension now verifies the server's certificate; the docker SQL Server's is self-signed, so the
  integration DSN says `TrustServerCertificate=true` as the e2e's already did.

## Testing

The mssql legs, now built: test-integration (both SQL Server scenarios), test-e2e (the door's mssql leg twice, the
types leg). A local database created before this spec needs the init re-run (`docker compose up sqlserver-init`),
and one holding an old policy catalog (`acl`, schema v10) a fresh `acltest`.

## As built (2026-10-13)

At 3645903 with duckdb bba7360: test-integration green (538 assertions, 17 files, both SQL Server scenarios);
test-e2e green with all four door legs (postgres, mssql, ducklake, pair) and the types leg with mssql.
