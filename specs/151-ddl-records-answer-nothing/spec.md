# Spec 151: the record a principal's DDL writes answers nothing

- **Status**: implemented
- **Date**: 2026-11-05
- **Author**: hugr lab (found while checking spec 150's quack batches, 2026-10-23; the owner placed it between spec
  150's stages 3 and 4)

## Summary

A principal's `CREATE`, `DROP` or `RENAME` in a schema that records its objects (an expansion, a `VIRTUAL ONLY`
grant, a view) and a session's `USE` are followed by a catalog record the rewriter appends. The record was a
`SELECT acl_…(…)`, which duckdb answers to the client like any query, under its call as the column's name. That name
carries the physical name and, for a view, the whole rewritten body. The record is now a `PRAGMA acl_…(…)`, run in one
query with the DDL. The DDL answers what a native one does: `Success`, no row. In a quack batch, the client's next
`SELECT` answers. A prepared DDL works, and a record that fails takes its `CREATE` back. Along the way an `EXPLAIN` of
such a DDL turned out to run the record in its place. It is refused.

## Problem

1. **The answer names what the principal never sees.** After `ACL ROLE "wide" CREATE VIEW vs.report AS SELECT id,
   amount FROM vs.orders`, the client got one row `true` under the column:

   `acl_register_view('sales', 'vs.report', 'SELECT id, amount FROM (SELECT COLUMNS(list_filter(*, … IN ('id',
   'amount', 'region')))) FROM (SELECT * FROM phys.lake.orders WHERE (tenant = acl_claim('tenant')))) AS orders',
   'wide')`

   That is the physical relation, the author's RLS predicate and the grant's column list. Nothing else shows a
   principal these: even `EXPLAIN` needs its own capability (spec 052). After `CREATE TABLE`, `RENAME` or `DROP` the
   column named the physical path (`acl_register_created('sales', 'vs.t2', 'phys.lake.t2', …)`), and after `USE` the
   session's ops id. The same name was a Flight `CREATE VIEW`'s announced schema.
2. **A quack batch lost its answer.** quack streams the first statement whose result is a query result. The record was
   one, so `CREATE TABLE …; SELECT …` answered the record's `true` instead of the `SELECT`, which a native quack
   server answers.
3. **A prepared DDL failed.** The DDL and its record were two statements: duckdb's `Prepare` refused them ("Cannot
   prepare multiple statements at once!"). Every Flight client prepares (GetFlightInfo), so a Flight `CREATE TABLE`
   in an expansion failed.
4. **A record that failed left the object behind.** The `CREATE` committed on its own, autocommit, before its
   record ran. A record that failed then (a read-only policy store) left a physical table no listing showed.
5. **`EXPLAIN` ran the record** (found here). `EXPLAIN` rewrites its inner statement. A `CREATE VIEW` is dropped for
   its record, so the record ran in the EXPLAIN's place: `EXPLAIN CREATE VIEW vs.ex AS …` made the view. An
   `EXPLAIN CREATE TABLE` wrote a record for a table that was never made. `EXPLAIN ANALYZE CREATE TABLE … AS` made the
   table with a record of its own statement.
6. **A Flight ingest that creates a table where a record is kept** (`mode=create` into an expansion) never worked: the
   door judges a load by the count its statement answers, and the statement did not prepare. Into a `VIRTUAL ONLY`
   schema the `CREATE` was dropped for its record, so the load was reported failed after the record had been written
   on the store's own connection, which the load's rollback does not reach.

## Design

- **The record is a PRAGMA** (`AclRewriter::AclRecord`): `PRAGMA acl_register_created | acl_register_existing |
  acl_register_view | acl_rename_relation | acl_drop_relation | acl_session_use (…)`. Each is registered beside the
  scalar of its name (`RECORD_PRAGMAS` in acl_admin_functions.cpp). `RunRecord` binds the scalar from the
  **system** catalog, never by the search path, so a macro of that name elsewhere is not what runs, and calls it once.
  The scalars stay: operators and tests call `acl_rename_relation` / `acl_drop_relation`, and their code is the
  record's.
  - A PRAGMA answers `Success` with no rows, the shape of a native DDL. duckdb binds it as a query result (bind_pragma),
    so a client sees an empty `Success`, not nothing.
  - A record that wrote nothing is an error: `acl_session_use` answered `false` for a session gone since. Nobody read
    that, and no answer carries it any more. The Flight door's session move (spec 135) read the `false`; it reads the
    error now.
- **A kept DDL and its record are one `MultiStatement`** (`RewriteStatements`): `[CREATE …, PRAGMA acl_…]`. duckdb runs
  an expansion as one query, so the two share one transaction in autocommit: a record that fails rolls the `CREATE`
  back. The pair is one statement for `Prepare`, which keeps it and expands it at each execution (spec 128). The
  Flight door already runs such a statement at GetFlightInfo (`Expands`). The answer is the expansion's row-returning
  statement, the record, which must be the last: one record per kept statement (an `InternalException` otherwise). A
  dropped statement (a view, a `USE`, a view's rename or drop) is its record alone, a top-level PRAGMA, as before.
- **quack skips the record** (a `sync.py` hunk in the generated fetch collector): `AclQuackRecordStatement` is true
  for a PRAGMA whose plan root calls one of the records, and the collector leaves the stream for the next statement
  that returns a result. With none left, quack's driver sends the last statement's result, the record's `Success`.
  A principal cannot forge one: its PRAGMA is one of two answered names (`table_info`, `show_tables`).
- **An ingest creates a table only where no record is kept** (a live alias's schema, a session temp): under the
  `ACL INGEST` prefix a `CREATE` that needs a record, or is `VIRTUAL ONLY`, is refused in the rewriter, before anything
  runs ("CREATE the table with SQL, then ingest into it"). One query answers its record's `Success`, never the
  `CREATE`'s count, so the door could not check the load.
- **`EXPLAIN` over a statement the rewrite drops or follows up is refused** ("EXPLAIN of a statement that writes the
  virtual catalog's record is not permitted under ACL - run the statement itself"). A DDL that writes no record (a
  live alias's schema) still explains.

## Enforcement & security

- The record's arguments are constants the rewriter decided (golden rule kept: no parameter is added). The PRAGMA is
  built as an AST, never as text.
- The call cannot be taken over: the PRAGMA is found among pragma functions, which no SQL creates, and the scalar it
  runs is the system catalog's.
- Unchanged: who may run the records (a principal cannot - `acl_*` is in the never set, its PRAGMA is refused by name)
  and what each writes.
- One ordering changes. The record's write lands on the store's own connection before the `CREATE`'s commit. A commit
  that fails after it (a remote home refusing at commit) leaves a record without its object, which
  `acl_check_catalog` reports (`source_missing`). Before, the reverse was possible: an object without its record, which
  nothing reported. Inside a client's explicit transaction this was already the order.

## Testing

- `test/sql/acl_ddl_records.test`:
  - every recorded DDL (`CREATE TABLE`, `… AS`, `CREATE VIEW`, `ALTER TABLE|VIEW … RENAME`, `DROP VIEW|TABLE`) answers
    no row, and each record is written;
  - a principal's own `PRAGMA acl_register_created` is refused;
  - `EXPLAIN [ANALYZE]` of a recorded `CREATE VIEW` / `CREATE TABLE [AS]` / `DROP` is refused and makes nothing (the
    file failed on `EXPLAIN CREATE VIEW` before the fix);
  - `EXPLAIN` of a DDL in a live alias explains.
- `test/cpp/test_acl_ddl_records.cpp`:
  - the column is `Success` for each DDL (sqllogictest cannot see names);
  - a batch answers `Success`, then the query's rows;
  - a prepared `CREATE TABLE … AS` and `CREATE VIEW` work, and the view's announced column is `Success`;
  - with a read-only policy store, the record's failure takes the `CREATE TABLE … AS` back: no table in the home.
- `test/cpp/test_acl_quack_embed.cpp`: through a real quack client, `CREATE TABLE …; SELECT 42` answers `42`, and a
  `CREATE VIEW` alone answers `Success`, no row.
- `test/cpp/test_acl_session_use.cpp`: a prepared `USE` whose session closed before it ran is an error.
- `test/cpp/test_acl_ingest_prefix.cpp`: under `ACL INGEST`, a `CREATE TABLE … AS SELECT * FROM arrow_scan()` into an
  expansion is refused and makes nothing. Into a live alias it passes the gate, to duckdb's own "ArrowScanFactory bind
  input".
- Before the fix, the probe answered the record's call as each column name, refused the prepared `CREATE TABLE … AS`
  ("Cannot prepare multiple statements at once!"), and `EXPLAIN CREATE VIEW` made the view.

## Alternatives considered

- **Shape the SELECT** (`SELECT r AS "Success" FROM (SELECT acl_…(…) AS r) WHERE r IS NULL`): hides the name. But it
  still takes quack's stream, still makes two statements for `Prepare`, and rests on the optimizer never folding the
  filter.
- **A statement duckdb answers with NOTHING** (`SET VARIABLE x = acl_…(…)`): quack would skip it unpatched. But it
  leaves a variable on the connection, which on a gateway's shared connection is the next principal's to read.
- **Mark the record by its text** for quack's collector (`context.GetCurrentQuery()`): the plan's root is structural
  and cannot be written by a principal.
- **Record before the DDL**: a `CREATE` that then fails would leave its record.

## Follow-ups

- A `CREATE TABLE … AS` in a recording schema answers `Success`, not the native `Count`. Before this spec it answered
  the record's `true`. duckdb answers an expansion with its row-returning statement, or an empty `Success` when there
  is none, so no shape of the record gives the count back. The same holds for an ingest that creates a table where a
  record is kept: it is refused; a door counting the created table itself could admit it.
