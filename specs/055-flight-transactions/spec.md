# Spec 055: transactions on the held connection

- **Status**: implemented
- **Date**: 2026-08-30
- **Author**: hugr-lab

## Summary

The Flight door reported `SQL_SUPPORTED_TRANSACTION_NONE` and refused any `transaction_id`, so a
driver with autocommit off could not work - `BeginTransaction` was `NotImplemented`, and DBeaver / the
ADBC driver's manual-commit mode fell back or failed. Since a session **is** a held duckdb connection
(spec 050), a transaction has a natural home: the session's own connection, where `BEGIN`/`COMMIT`/
`ROLLBACK` already span the session's RPCs. This implements the Flight protocol's transaction actions
over that: `BeginTransaction` opens a transaction on the session connection and mints a
`transaction_id`, statements carrying it are validated against the session's open transaction, and
`EndTransaction` commits or rolls back. Autocommit-off now works through the real driver.

## Problem

- `FLIGHT_SQL_SERVER_TRANSACTION` was `NONE`; `BeginTransaction`/`EndTransaction` were the base class's
  `NotImplemented`. A DBAPI/JDBC client with autocommit off could not begin a transaction.
- Every statement path refused a non-empty `transaction_id` outright.
- The internal atomicity wrappers (the prepared-update batch's `BEGIN`/`COMMIT`, spec 048) assumed no
  outer transaction, so once one could exist they would nest a second `BEGIN` and fail.

## Design

### A transaction lives on the session's connection

- `SessionConn` gains `txn_id` (empty = none), guarded by the same `exec` lock as the connection. A
  session holds at most one transaction, because it holds one connection.
- `BeginTransaction` (needs a cookie session - a per-call one has nowhere to hold it): `BEGIN
  TRANSACTION` on `ConnFor(handle)`, mint an opaque `transaction_id`, store it on the SessionConn,
  return it. A second begin while one is open is refused (savepoints are a follow-up).
- Statements carry the `transaction_id`; `ValidateTxnLocked` (called under `conn->exec`, where the
  statement already routes since spec 050) checks it equals the session's open one. Empty is
  autocommit and always fine; a foreign or stale id is refused rather than run outside its
  transaction. The statement then executes on the session connection, which is in the transaction -
  so nothing beyond the check is needed; the connection *is* the transaction context.
- `EndTransaction` commits or rolls back on the session connection and clears `txn_id`, whichever way
  duckdb's own `COMMIT`/`ROLLBACK` goes, so a failed commit does not strand the session in a
  transaction it can no longer name.
- `FLIGHT_SQL_SERVER_TRANSACTION` becomes `SQL_SUPPORTED_TRANSACTION_TRANSACTION`.

### The internal atomicity wrapper joins, does not nest

The prepared-update batch (executemany, spec 048) wrapped itself in `BEGIN`/`COMMIT` for "one batch,
one outcome". When the client already holds a transaction it now **joins** it (`owns_txn =
!HasActiveTransaction()`), leaving the commit to the client - the same guard the ingest path already
used (spec 052). Ingest still refuses a `transaction_id`: it must own its transaction for the
row-count cross-check to decide before commit.

### Lifecycle

A transaction dies with its connection: session end (idle / `exp` / `CloseSession` / stop) destroys
the `Connection`, and duckdb rolls back any open transaction natively. No transaction registry, no
separate sweep - the `txn_id` is a field on the connection that is already swept.

## Enforcement & security

- A `transaction_id` is validated against the caller's own session connection, and statements execute
  only on that connection - a stolen id cannot move execution onto another session's transaction (it
  would be validated against the thief's own connection and refused).
- The ACL is unchanged inside a transaction: RLS, capabilities and the write-predicate check all apply
  per statement, at execute time - a cross-tenant write is refused inside a transaction exactly as in
  autocommit (proven in the e2e), because the rewrite is not a commit-time check.
- Fail-closed: no cookie session -> no transaction; a second begin -> refused; a foreign id ->
  refused; a session that ends mid-transaction -> rolled back by connection teardown.

## Testing

- `test/e2e/flight/adbc.sh` (the real ADBC driver, manual-commit): a rolled-back insert does not land;
  a committed one does; an uncommitted insert is visible to its own transaction (read-your-writes) and
  gone after rollback; a cross-tenant write is refused inside a transaction. The per-statement RLS and
  ingest checks run with autocommit on (a new `connect(autocommit=...)` toggle), since spec 055 makes
  the driver honour DBAPI manual-commit by default.
- One ADBC-client wrinkle worth recording: `cursor.execute()` of a DML runs through the query path and
  its DoGet (the actual execution) is *deferred* until the result is read, so the test forces it with
  `fetchall()` to keep the write inside the transaction. This is the Python dbapi driver's laziness,
  not the server's - a JDBC `executeUpdate` (DBeaver) runs eagerly.

## Alternatives considered

- **A `transaction_id` -> dedicated-connection registry**, decoupled from the session (the way a
  server whose transports do not share a session would need). Rejected: our session already *is* a
  connection and the cookie pins every RPC of a connection to it, so the transaction has an owner
  already; a second registry would also split temp tables (on the session connection) from the
  transaction. The cookie session is the transaction's home.
- **Savepoints** (`BeginSavepoint`/`EndSavepoint`) - left unimplemented; duckdb has no savepoints, and
  no driver requires them for basic manual-commit.

## Follow-ups

- Savepoints, if a client ever needs them (duckdb support permitting).
- A transaction idle bound: today an abandoned transaction is reclaimed when its session is swept
  (idle / `exp`); a shorter bound specific to open transactions (which hold locks) could be worth it
  under contention, but the session sweep already caps the lifetime.
