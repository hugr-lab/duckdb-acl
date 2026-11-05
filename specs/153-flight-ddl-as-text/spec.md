# Spec 153: a client's DDL over Flight runs as text

- **Status**: implemented
- **Date**: 2026-11-05
- **Author**: hugr lab (the owner chose the way, 2026-11-05, after spec 151)

## Summary

The Flight door ran every client statement through `Connection::Prepare`. A principal's `CREATE TABLE`, `DROP TABLE`
or table `RENAME` in a schema that records its objects is the DDL and its catalog record: two statements, which
duckdb's `Prepare` refuses ("Cannot prepare multiple statements at once!"). So such DDL never worked over Flight,
before spec 151 or after it. It worked through quack and a gateway, which run a text with `Query`. Now the door runs a
client's DDL the same way: as text, through `Query`, on the session's connection.

## Problem

- **The DDL failed.** A Flight client cannot create, drop or rename a table in an expansion
  (`CREATE VIRTUAL SCHEMA c.x FROM …`) or in a `VIRTUAL ONLY` schema. DBeaver's create-table dialog and a dbt model
  over ADBC are both such clients. A live alias's schema works, because it keeps no record: its DDL is one statement.
- **Why not the other ways** (the owner's decision):
  - one `MultiStatement` for the DDL and its record was tried and dropped in spec 151;
  - an `acl_*` function that runs the DDL would run it on another connection - outside the client's transaction,
    without its session's USE, temp tables and `AclConnection`, and with the CTAS's source read through SQL from
    inside a function.

## Design

- **What runs as text** (`RunsAsText`): the client's statement, past the markers it writes itself, read by the plain
  parser as ONE `CREATE` (not a `SECRET`), `DROP` or `ALTER`, with no parameter. Management statements, `SET` / `USE`,
  queries and DML keep the prepared path, unchanged.
- **How it runs** (`RunAsText`): the text behind the session's prefix goes through `Connection::Query` on the
  session's connection, under its statement lock. The door's usual guards run first: the moved-session transaction
  guard (spec 135) and the transaction id (spec 055). The temp-scan seam (spec 050) and the profile arming (spec 074)
  run around it, as before.
  - The parser override decides the statement once, at that parse, as on a gateway: one audit event, one profile
    note, one lineage run.
  - The answer is the last statement's result: a DDL's own `Success`, or its record's (spec 151).
  - A failed statement in the run is the call's error.
- **Where** - the reservation kind `text_command` (no `PreparedStatement`; `executed` holds the answer):
  - ad hoc `GetFlightInfo` runs it then, as spec 111 runs every count, and its DoGet answers the kept result;
  - `ExecuteUpdate` (DoPut) runs it and answers the counts the run's results carry - 0 for a DDL with a record,
    whose answer is the record's `Success`;
  - `CreatePreparedStatement` keeps only the text: an empty dataset and parameter schema, nothing decided yet. Each
    execution decides it again under the policy of the moment: `GetFlightInfo` on the handle, its `DoPut` update,
    or a `DoGet` no `GetFlightInfo` preceded;
  - binding parameters to it is refused: "a DDL statement takes no parameters".

## Enforcement & security

- Nothing about the decision moves. The same override reads the same composed prefix, `ACL SESSION '<h>'` plus the
  call's trace and lineage markers, and the rewriter refuses or rewrites exactly as for a prepared statement. The
  door only stops preparing what it never streams.
- A prepared DDL is decided at each execution, no longer at its creation. A policy change in between counts, so
  spec 152's "executes as decided" no longer holds for DDL.
- The owner check of a ticket or handle (spec 047) is unchanged.

## Testing

`test/e2e/flight/adbc_client.py`, through the real ADBC driver, in the expansion `c.made` (bootstrap.sql):
- `CREATE TABLE made.t AS …` (GetFlightInfo) answers no row, then `ALTER TABLE … RENAME` and a read of the new name;
- `DROP TABLE` through `execute_update` (DoPut) removes the record: a read is refused as "no access";
- a prepared `CREATE TABLE … AS` runs through `execute_update` and reads back;
- a `cursor.execute` of a DDL with a bound parameter is refused: "a DDL statement takes no parameters".

Each of the first three failed before with "Cannot prepare multiple statements at once!". The rest of
`make test-flight` passes unchanged: run, tls, certificate_reload, auth, ca_bundle, drain, stream, admin.

## Alternatives considered

- **Prepare first, and fall back to `Query` on "Cannot prepare multiple statements"**: the override would decide the
  statement twice, giving two audit events and two lineage captures. It would also hang the path on an error text.
- **Every client command as text** (`SET`, `USE`, management): those prepare today, and a management call may carry
  parameters (spec 117), which `Query` cannot bind. Only DDL needs it.

## Follow-ups

- `ExecuteUpdate` of a `CREATE TABLE … AS` with a record answers 0, not the rows written. duckdb's result chain for a
  text of several statements carries only the last one's answer.
