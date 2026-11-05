# Spec 153: a client's DDL over Flight runs as text

- **Status**: implemented
- **Date**: 2026-11-05
- **Author**: hugr lab (the owner chose the way, 2026-11-05, after spec 151)

## Summary

The Flight door ran every client statement through `Connection::Prepare`. In a schema that records its objects, a
principal's `CREATE TABLE`, `DROP TABLE` or table `RENAME` is the DDL plus its catalog record: two statements, and
duckdb's `Prepare` refuses that ("Cannot prepare multiple statements at once!"). So such DDL never worked over Flight,
before spec 151 or after it. Quack and a gateway run a text with `Query`, so there it worked. Now the door runs a
client's DDL the same way: as text, through `Query`, on the session's connection.

## Problem

- **The DDL failed.** A Flight client cannot create, drop or rename a table in an expansion
  (`CREATE VIRTUAL SCHEMA c.x FROM …`) or in a `VIRTUAL ONLY` schema. DBeaver's create-table dialog and a dbt model
  over ADBC are both such clients. A live alias's schema works: it keeps no record, so its DDL is one statement.
- **The other ways, rejected** (the owner's decision):
  - one `MultiStatement` for the DDL and its record was tried and dropped in spec 151;
  - an `acl_*` function that runs the DDL would run it on another connection. It would then be outside the client's
    transaction, and without the session's USE, temp tables and `AclConnection`. The CTAS's source would be read as
    SQL from inside a function.

## Design

- **What runs as text** (`acl::ClientTextIsDdl`, acl_admin_sql.cpp, next to `ClientTextIsMgmt`). The plain parser
  reads the client's statement, past the markers it writes itself. It runs as text when it is ONE `CREATE`, `DROP`
  or `ALTER` with no placeholder.
  - `CREATE SECRET` is excluded: it answers a row, so the door's prepared path takes it as a query. A `DROP SECRET`
    answers none, so it is DDL here.
  - Management statements, `SET` / `USE`, queries, DML and a DDL with a placeholder keep the prepared path.
- **How it runs** (`RunDdlText`): the text, behind the session's prefix, goes through `Connection::Query` on the
  session's connection.
  - First, under its statement lock, the door's usual guards run: the moved-session transaction guard (spec 135)
    and, on the ad hoc paths, the transaction id (spec 055).
  - The temp-scan seam (spec 050) and the profile arming (spec 074) run around it.
  - The parser override decides the statement at that parse, once, as on a gateway: one statement event and one
    profile for the run (a reviewer counted them on each path).
  - `Query` answers the error alone when a statement fails. Otherwise its answer is the last statement's result: the
    DDL's own `Success`, or its record's (spec 151).
- **Where**: a reservation of kind `ddl_text`. It has no `PreparedStatement`; `executed` holds the answer.
  - Ad hoc `GetFlightInfo` (`DdlTicketInfo`) runs it, as spec 111 runs every count, and its DoGet answers the kept
    result.
  - `ExecuteUpdate` (DoPut) runs it and answers its count: 0 for a DDL with a record.
  - `CreatePreparedStatement` keeps only the text and announces an update (an empty dataset and parameter schema).
    Nothing is decided at that point.
  - Each execution decides the DDL again, under the policy of that moment (`RunPreparedDdl`). That means a
    `GetFlightInfo` on the handle, its DoPut update, or a DoGet that no `GetFlightInfo` preceded.
  - It runs on the session that executes it: `ConnFor(caller)`. A handle belongs to the principal, and another session
    of it may run it, such as a cookie-less client's next call. The prefix and the connection are therefore always
    one session's.
  - The handle's reservation holds the text alone and is never written after its creation. Concurrent calls on one
    handle (two per-call sessions) share nothing to race on. A `GetFlightInfo` answers through a single-use ticket of
    its own, as the ad hoc path does; a DoGet with no `GetFlightInfo` before it streams through a reservation of its
    own.
  - Binding parameters to it is refused: "a DDL statement takes no parameters".
- **A single-use ticket is no prepared handle**: `FindReservation` skips it. Before this spec it accepted a ticket's
  id as a handle; a DDL ticket would now run again through it.

## Enforcement & security

- The decision stays where it was. The same override reads the same composed prefix: `ACL SESSION '<h>'`, then the
  call's trace and lineage markers. It refuses or rewrites as it would for a prepared statement. The door only stops
  preparing what it never streams. A reviewer found no second statement smuggled through `Query`: the classification
  parses the same normalized text with the same grammar.
- **What Flight newly reaches**: everything the gateway and quack already reached for a principal's DDL. That
  includes a `DROP` or `CREATE OR REPLACE` of a physical table in an expansion that has no record. The owner decided
  (2026-11-05) that with `drop` on an expansion schema or catalog the drop is physical.
- A prepared DDL is decided at each execution, not at its creation. A policy change in between counts. This is the
  exception to spec 047's rule that a reservation holds what was decided at its creation.
- The owner check of a ticket or handle (spec 047) is unchanged.

## Testing

- `test/cpp/test_acl_client_mgmt.cpp`: the classification.
  - Run as text: CREATE (TABLE, AS, VIEW), DROP, ALTER, `DROP SECRET`, behind a TRACE marker or `ACL NATIVE`, spaced
    with U+00A0, a trailing `;`.
  - Kept prepared: `CREATE SECRET`, a `$1` / `?`, two statements, management, a query, DML, a `SET`, an unreadable
    text.
- `test/e2e/flight/run.sh` (raw Flight SQL), in the expansion `c.made` (bootstrap.sql):
  - the ad hoc `CREATE TABLE … AS` and its read;
  - a prepared DDL's empty dataset schema;
  - a foreign transaction id refused on a DDL;
  - a prepared `DROP` refused at execution once `drop` was revoked after its creation;
  - an ad hoc `DROP`.
- `test/e2e/flight/adbc_client.py` (the real ADBC driver; its DBAPI prepares every text):
  - `CREATE TABLE … AS`, `ALTER TABLE … RENAME` and a read of the new name;
  - `DROP TABLE` through `execute_update` answers 0 and takes the record with it;
  - a prepared `CREATE TABLE … AS` through `execute_update`;
  - a DDL with a bound parameter refused;
  - a `CREATE TABLE` accepted inside a manual-commit transaction, and committed.
- Before the change, each DDL check that runs a DDL failed with "Cannot prepare multiple statements at once!"; the
  transaction-id refusal held before too (it is checked ahead of the Prepare), and is kept on the new path.
- The rest of `make test-flight` passes unchanged: tls, certificate_reload, auth, ca_bundle, drain, stream, admin.

## Alternatives considered

- **Prepare first, and fall back to `Query` on "Cannot prepare multiple statements"**: the override would decide the
  statement twice, which means two audit events and two lineage captures. It would also tie the path to the wording
  of an error.
- **Every client command as text** (`SET`, `USE`, management): those already prepare, and a management call may carry
  parameters (spec 117), which `Query` cannot bind. Only DDL needs it.

## Follow-ups

- A DDL with a placeholder (`CREATE TABLE made.q AS SELECT ? AS x`) stays prepared. In a schema that records its
  objects it still fails with "Cannot prepare multiple statements"; in a live alias it works, as it did before.
- `ExecuteUpdate` of a `CREATE TABLE … AS` with a record answers 0, not the rows written. duckdb's `Query` keeps the
  record's answer, which replaces the CTAS's count.
- Inside a client's transaction, a `ROLLBACK` does not yet take back a record (spec 151's follow-up). Flight now
  reaches that case too.
