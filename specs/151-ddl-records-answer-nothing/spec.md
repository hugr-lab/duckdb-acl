# Spec 151: the record a principal's DDL writes answers nothing

- **Status**: implemented
- **Date**: 2026-11-05
- **Author**: hugr lab (found while checking spec 150's quack batches, 2026-10-23; the owner placed it between spec
  150's stages 3 and 4; items 4-6 found by this spec's reviews)

## Summary

The rewriter appends a catalog record after two kinds of statement. One is a principal's `CREATE`, `DROP` or
`RENAME` in a schema that records its objects: an expansion, a `VIRTUAL ONLY` grant, a view. The other is a session's
`USE`. The record was a `SELECT acl_…(…)`, which duckdb answers to the client like any query, under its call as the
column's name. That name carries the physical name, and for a view the whole rewritten body.

The record is now a `PRAGMA acl_…(…)`. The client gets `Success` with no row, as for a native DDL statement (a
native `CREATE TABLE … AS` answers its count). A quack batch now answers the client's own `SELECT`.

The reviews found three more problems on the same path, all older than this spec, and each is fixed here:
- an `EXPLAIN` of such a DDL ran the record in its place;
- an `IF NOT EXISTS` adopted a physical table the expansion did not show;
- inside a client's transaction, the record lost the object's type facts.

## Problem

1. **The answer named what the principal never sees.** After `ACL ROLE "wide" CREATE VIEW vs.report AS SELECT id,
   amount FROM vs.orders`, the client got one row `true` under the column:

   `acl_register_view('sales', 'vs.report', 'SELECT id, amount FROM (SELECT COLUMNS(list_filter(*, … IN ('id',
   'amount', 'region')))) FROM (SELECT * FROM phys.lake.orders WHERE (tenant = acl_claim('tenant')))) AS orders',
   'wide')`

   - The name holds the physical relation, the author's RLS predicate and the grant's column list. Nothing else
     shows these to a principal: even `EXPLAIN` needs its own capability (spec 052).
   - After a `CREATE TABLE`, a `RENAME` or a `DROP`, the column named the physical path
     (`acl_register_created('sales', 'vs.t2', 'phys.lake.t2', …)`).
   - After a `USE`, it named the session's ops id.
   - A Flight `CREATE VIEW` announced the same name as its schema.
2. **A quack batch lost its answer.** quack streams the first statement whose result is a query result. The record
   was one, so `CREATE TABLE …; SELECT …` answered the record's `true`. A native quack server answers the `SELECT`.
3. **A `USE` whose session was gone** answered `false`, which nobody read, and the client went on as if it had worked.
4. **`EXPLAIN` ran the record.** `EXPLAIN` rewrites its inner statement, and the record went after the `EXPLAIN`:
   - `EXPLAIN CREATE VIEW vs.ex AS …` made the view: the `CREATE VIEW` is dropped for its record, so the record ran in
     the EXPLAIN's place;
   - `EXPLAIN CREATE TABLE` wrote a record for a table that was never made;
   - `EXPLAIN DROP TABLE vs.orders` removed the record and left the table;
   - `EXPLAIN ANALYZE CREATE TABLE … AS` made the table and recorded it, though `EXPLAIN` is not a way to create one.
5. **`IF NOT EXISTS` adopted a table.** In an expansion, the rewriter judged the name only against the records. Take
   a physical table with no record: made after the expansion, or dropped from it on purpose (`DROP VIRTUAL TABLE`).
   `CREATE TABLE IF NOT EXISTS vs.salaries (x INT)` was then a native no-op, and its record handed the role that
   table, data included.
6. **Facts lost in a transaction.** The record probes the object on a connection of the store's: its type facts
   (spec 099), and a view's columns (spec 010). Inside a client's transaction that connection cannot see a table made
   there, so nothing was stored. dbt's swap (`CREATE m__tmp …; ALTER … RENAME TO m`, one transaction) is that case.
   Under `acl_enum_types = 'varchar'` the ENUM labels were exposed, and `acl_check_catalog` reported `types_stale` /
   `schema_stale`.
7. **Flight ingest with a record** (`mode=create` into an expansion or a `VIRTUAL ONLY` schema) never worked:
   - the door prepares a load, and a `CREATE` with its record is two statements, which do not prepare;
   - into a `VIRTUAL ONLY` schema the `CREATE` was dropped for its record. The load was reported failed after the
     record had been written on the store's own connection, where the load's rollback does not reach.

## Design

- **The record is a PRAGMA** (`AclRewriter::AclRecord`): `PRAGMA acl_register_created | acl_register_existing |
  acl_register_view | acl_rename_relation | acl_drop_relation | acl_session_use (…)`.
  - Each is registered beside the scalar of its name (`RECORD_PRAGMAS` in acl_admin_functions.cpp). `RunRecord` binds
    that scalar from the **system** catalog, never by the search path, and calls it once, so a macro of the same name
    elsewhere is not what runs.
  - The scalars stay: operators and tests call `acl_rename_relation` / `acl_drop_relation`.
  - The record stays a statement of its own, right after its DDL. A `CREATE` that fails stops the batch before its
    record.
  - A PRAGMA answers `Success` with no rows. duckdb binds it as a query result (bind_pragma), so a client sees an
    empty `Success` result.
  - A record that wrote nothing is an error. That is `acl_session_use` for a session gone since, which answered
    `false`. The Flight door's session move (spec 135) read that `false`; it now reads the error.
- **quack skips the record** (a `sync.py` hunk in the generated fetch collector).
  - `AclQuackRecordStatement` is true for a PRAGMA whose plan root calls one of the records. The collector then
    leaves the stream for the next statement that returns a result.
  - If none is left, quack's driver sends the last statement's result: the record's `Success`.
  - A principal cannot forge a record. Its PRAGMA is one of two answered names (`table_info`, `show_tables`), which
    become SELECTs.
- **`EXPLAIN` of a statement with a record is refused**: "EXPLAIN of a statement that writes the virtual catalog's
  record is not permitted under ACL - run the statement itself". Every `RENAME` carries a record. A DDL with none
  explains (a `CREATE` in a live alias's schema), and a no-op answers the empty `Success` it always did.
- **`IF NOT EXISTS` with no record is the physical name's question.** When the target needs a record and has none
  (`AdmitRecordConflict` passed), the physical `CREATE` turns its `IF NOT EXISTS` into a plain `CREATE`. duckdb then
  refuses a taken name ("already exists"), and the record never runs. A recorded name stays a no-op. A free name is
  made and recorded. A plain `CREATE` of a taken name was already refused natively (spec 051), so the error reveals
  nothing new.
- **A record made in a client's transaction is probed again at its commit** (`RefreshAtCommit`, a
  `ClientContextState` beside spec 113's `RecordRenameUndo`, since spec 154 `RecordUndo`).
  - `acl_register_created` and `acl_register_view` queue their name; `acl_rename_relation` queues the new one, so
    dbt's swap is refreshed under the name that commits.
  - After the commit, `PolicyStore::CatalogRefreshSchema` (what `ANALYZE` runs) re-probes each one: type facts, a
    view's columns, an RLS verdict.
  - A rollback drops the queue. A refresh that fails leaves `types_stale` / `schema_stale` to `acl_check_catalog`.
  - In autocommit the DDL has committed before its record runs, so the record's own probes see it.
- **An ingest creates a table only where no record is kept** (a live alias's schema, a session temp). Under the
  `ACL INGEST` prefix, a `CREATE` that needs a record or is `VIRTUAL ONLY` is refused in the rewriter, before anything
  runs: "CREATE the table with SQL, then ingest into it".

## Enforcement & security

- The record's arguments are constants the rewriter decided, so the golden rule holds: no parameter is added. The
  PRAGMA is built as an AST, never as text.
- The call cannot be taken over.
  - The PRAGMA is looked up among the pragma functions, which no SQL creates.
  - The scalar it runs is the system catalog's.
- Who may run the records is unchanged. A principal cannot: `acl_*` is in the never set, and its PRAGMA is refused by
  name. What each record writes is unchanged too.
- Fixed gate gaps:
  - `IF NOT EXISTS` adopting a table (5) handed out read access nobody granted;
  - `EXPLAIN` (4) created and dropped records outside the rights the statement itself is judged by.

## Testing

- `test/sql/acl_ddl_records.test`:
  - every DDL that writes a record answers no row: `CREATE TABLE`, `… AS`, `CREATE VIEW`,
    `ALTER TABLE|VIEW … RENAME`, `DROP VIEW|TABLE` and a `VIRTUAL ONLY` register. Each record is written;
  - a principal's own `PRAGMA acl_register_created` is refused;
  - `EXPLAIN [ANALYZE]` of a recorded `CREATE VIEW`, `CREATE TABLE [AS]` and `DROP` is refused and makes nothing:
    `orders` is still listed after the refused `EXPLAIN DROP`. The file failed on `EXPLAIN CREATE VIEW` before the
    fix;
  - an `EXPLAIN` of a no-op answers as before, and one in a live alias explains;
  - `CREATE TABLE IF NOT EXISTS` over an unrecorded physical table is refused, and the table stays unreadable. Over a
    recorded name it is a no-op; a free name is made;
  - type facts: a CTAS of an ENUM column stores them in autocommit and inside `BEGIN … COMMIT`, and dbt's swap in one
    transaction stores them under the new name;
  - a view over a table made in the same transaction gets its columns at commit.
- `test/cpp/test_acl_ddl_records.cpp`:
  - the column is `Success` for each DDL. sqllogictest cannot see names;
  - a batch answers `Success`, then the query's rows;
  - a prepared `CREATE VIEW` announces `Success`.
- `test/cpp/test_acl_quack_embed.cpp`, through a real quack client:
  - `CREATE TABLE …; SELECT 42` and `USE c; SELECT 7` answer the `SELECT`;
  - a `CREATE VIEW` alone answers `Success` with no row.
- `test/cpp/test_acl_session_use.cpp`:
  - `USE` answers `Success` with no row;
  - a prepared `USE` whose session closed before it ran is an error.
- `test/cpp/test_acl_ingest_prefix.cpp`, under `ACL INGEST`:
  - a `CREATE TABLE … AS SELECT * FROM arrow_scan()` into an expansion or a `VIRTUAL ONLY` schema is refused and
    records nothing;
  - into a live alias it passes the gate, to duckdb's own "ArrowScanFactory bind input".
- `test/e2e/flight/adbc_client.py`: the real ADBC driver's `CREATE VIEW` / `DROP VIEW` in an expansion (`c.made`,
  bootstrap.sql) answer `Success` with no row, and the view reads the author's slice.

## Alternatives considered

- **The DDL and its record as one `MultiStatement`** (built, then dropped after review). It made the pair atomic and
  preparable: Flight's prepared `CREATE TABLE` in an expansion would have worked. But one expansion is one query:
  - the execution profile (spec 074) kept only the last statement's plan, so a CTAS profiled as its record;
  - a deferred `Prepare` fires no QueryBegin. A Flight statement prepared on one gRPC thread and run on another lost
    its decision note, and left that note for the next execution on the preparing thread;
  - the record's probes ran before the CREATE committed.
  Each is fixable, but together they are a project of their own.
- **Shape the SELECT** (`SELECT r AS "Success" FROM (SELECT acl_…(…) AS r) WHERE r IS NULL`): it hides the name. But
  it still takes quack's stream, and it depends on the optimizer never folding the filter.
- **A statement duckdb answers with NOTHING** (`SET VARIABLE x = acl_…(…)`): quack would skip it unpatched. But it
  leaves a variable on the connection, which on a gateway's shared connection is the next principal's to read.
- **Mark the record by its text** for quack's collector (`context.GetCurrentQuery()`): the plan's root is
  structural, and a principal cannot write it.

## Follow-ups

- **Flight and a table's DDL with a record.** The door prepared every statement, and a `CREATE TABLE [AS]`, a
  `DROP TABLE` or a table's `RENAME` in an expansion is two statements: "Cannot prepare multiple statements at once!"
  (before this spec too). Done by spec 153: the door runs a client's DDL as text.
- **A record follows the client's `ROLLBACK`**: done by spec 154 (each record write keeps the names' rows before and
  after it, taken back at the ROLLBACK by a rule that never undoes over another write).
- **A record that fails after its `CREATE` committed** leaves an object with no record, as before. `acl_check_catalog`
  reports it (`expansion_stale`).
- **A `CREATE TABLE … AS` with a record** answers `Success`, not the native `Count`. Before this spec it answered the
  record's `true`.
- **`DROP` and `CREATE OR REPLACE` of a physical table with no record**, in an expansion and with `drop` held, act on a
  table the expansion does not show. Decided by the owner, 2026-11-05: with `drop` on an expansion schema or catalog,
  the drop is physical. It stays as it was (`DROP TABLE IF EXISTS` of an unrecorded table is tested in
  test_acl_session_use.cpp).
- **The binder's "Did you mean"**: a principal's `DROP TABLE vs.nothing` answers `Did you mean
  "aclcat.acl.function_grants"?`. duckdb's suggestion names objects of other catalogs, the policy store's included.
  This is older than this spec, and the next spec takes it.
- **Inside a client's transaction**, a `RENAME`'s definition lineage (`NoteDefinitionLineage(…, "CREATE")`) is queued
  before the commit. The worker may bind the new name before it is visible. This is older than this spec too.
- `test/e2e/flight/bootstrap.sql`'s `c.made` must stay empty outside adbc_client.py: run.sh asserts GetDbSchemas
  exactly, and an empty expansion is not listed.
