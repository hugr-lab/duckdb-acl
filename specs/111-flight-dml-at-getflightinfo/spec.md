# Spec 111: a statement that answers only a count runs where Flight SQL says it runs

- **Status**: implemented
- **Date**: 2026-10-09
- **Found by**: the lineage spike (Python, ADBC Flight SQL), 2026-10-09
- **Amends**: spec 047 (the reservation), spec 070 (the stream)
- **Decisions (owner, 2026-10-09)**:
  - DoPut is the main path for DML and DDL;
  - executing at GetFlightInfo covers the clients that never take DoPut;
  - the cluster rules go in the docs.

## Problem

A write sent as a query is lost, with no error, when its result is never read.

- **The client.** ADBC's Python DBAPI sends every `cursor.execute()` down the query path: it
  prepares, then calls `execute_query`, and never `execute_update`. The Go driver starts the DoGet in
  a goroutine and cancels it when the cursor is released.
- **What the spike saw.** With an `INSERT` nobody fetched, the DoGet was cancelled 17 µs in and
  never reached the node. The node runs a statement only at DoGet (specs 047/070), so the write did
  not happen.
- **What the client was told.** Nothing: no error, and the count before and after was 62 → 62.
- **Elsewhere.** GizmoSQL, also a DuckDB server, saw the same thing (gizmosql #134).

The protocol puts execution elsewhere. `FlightSql.proto` says of `CommandStatementQuery` and
`CommandPreparedStatementQuery` "GetFlightInfo: execute the query" / "execute the prepared statement
instance". The update commands are "for the RPC call DoPut to cause the server to execute the
included SQL update". `Flight.proto`: "GetFlightInfo doesn't return until the query is complete".
A client that wants only a schema has GetSchema, which executes nothing.

## Design

**1. DoPut is the main path for DML and DDL.** A prepared statement that answers only a count
(`ResultEagerness::FORCED`: INSERT / UPDATE / DELETE / MERGE / CTAS / DDL) is announced as an update:

- **The schema.** CreatePreparedStatement answers it with an **empty dataset schema**. JDBC reads an
  empty schema as an update and executes it through DoPut (`DoPutPreparedStatementUpdate`, which runs
  the statement in the call).
- **`is_update`.** Flight SQL added an `is_update` flag to the prepared-statement result in June 2026
  (apache/arrow #49498). Newer ADBC (Go, arrow-adbc #4161) and JDBC (arrow-java #1064) take DoPut on
  it. Our Arrow (24) does not carry the field yet; we set it when the pin moves to an Arrow that does.
  The empty schema covers JDBC until then.
- **Who is unaffected.** A statement that returns rows (SELECT, `INSERT … RETURNING`) keeps its schema.

**2. GetFlightInfo executes a statement that answers only a count**, for every client that sends
DML down the query path anyway: DBAPI's `execute`, an ad-hoc `CommandStatementQuery` (which has no
`is_update`), older drivers, tools that never tell a query from an update.

- **The ad-hoc query.** After Prepare, under the same statement lock, such a statement executes in
  GetFlightInfo. Its result (one row, the count) waits in the reservation, and the DoGet answers it
  without running anything again. A failure is GetFlightInfo's answer, so the client hears the
  refusal on its execute.
- **The prepared query.** GetFlightInfo on such a statement executes it with the parameters bound
  then, keeps the result, and the next DoGet takes it. Two GetFlightInfos are two executions, as the
  protocol says. A DoGet with no kept result executes, as before.
- **Unchanged.**
  - A statement that streams rows is still submitted lazily at DoGet (spec 070). Running it early
    would hold a whole result for a client that may never pull it.
  - The DoPut paths are unchanged: they always ran in the call.
- **Lifetime.** A result nobody fetched lives with its reservation and is swept with it. A short
  bound of its own is a follow-up if it is ever needed: it is a single row.

**3. The cluster rules, in the docs** (`website/docs/serving.md`, the clients' and the cluster pages):

- **One node per pair.** A reservation lives on the node that made it. GetFlightInfo and its DoGet
  must reach the same node, which is what the front's sticky session already guarantees. A front
  that spreads one session over several nodes breaks the ticket today: `unknown ticket`.
- **DoPut is the clean path.** It is one RPC, so there is no window between two calls and nothing
  left behind on the node. That is why it is the main path above.
- **A retry may double a write.** DML through the query path that fails at DoGet *may have been
  written*. A node that dies between the two calls, or an answer lost after the commit, looks the
  same to the client.
  - This is not new: any DML RPC whose answer is lost after the commit has it, and so has DoPut.
  - Writes that may be retried must be idempotent (MERGE, a key) or held in a client transaction.
  - Before this spec the window did not exist only because the write was lost instead.

## Enforcement & security

Nothing new is decided:

- **The statement.** It was already rewritten and bound under its owner at GetFlightInfo (spec 047).
- **The execution.** It runs on the session's own connection, under the statement lock and the
  transaction check.
- **The ticket.** It still redeems only for its owner; a foreign ticket gets the same refusal as
  before.
- **Profile and lineage.** An execution at GetFlightInfo is profiled and gets its lineage there: one
  run per execution, as before.

## Testing

**The door's own e2e** (`test/e2e/flight/run.sh`, `adbc.sh`):

- **An INSERT sent as a query and never fetched** is written.
- **A fetched one** answers its count once.
- **A refused one** fails at execute.
- **DBAPI.**
  - `cursor.execute(INSERT)` with no `fetchall()` writes.
  - A manual-commit transaction without fetches keeps commit and rollback.
- **The prepared DML's dataset schema** is empty in CreatePreparedStatement.

**The real clients, on the spike environment** (Spark / Python / dbt of 2026-10-09, run again on the
fixed node):

- **Spark JDBC.**
  - The write (`executeBatch`) and the read.
  - The DDL of `mode("overwrite")` and of `truncate`.
- **Python ADBC.** `execute` without fetch, `executemany`, `adbc_ingest`.
- **JDBC `execute()` with a DML** goes through DoPut, as seen in the node's door events.
- **dbt over quack** is unchanged.

## Alternatives considered

- **Execute only at DoGet, and refuse the session's next statement when a count was never
  fetched.** The write is lost loudly instead of silently, but it is still lost. It contradicts the
  protocol, and the one client most affected (DBAPI) would fail on code that is correct for it.
- **Execute at the session's next statement.** The write would run when DoGet never came, at a
  moment nobody asked for, with its error answered to the wrong call.
- **Tell clients to fetch.** That is a workaround, not a fix: DBAPI, JDBC `execute()` and BI tools all
  treat execute as having run.

## As built (2026-10-09)

- **`AnswersOnlyCount`.** It judges the bound return type (`!= QUERY_RESULT`). duckdb settles a
  prepared statement's properties only once its parameters bind, and a parameter it cannot type
  leaves them unsettled; a grant's predicate wrapping `VALUES (?, …)` (spec 024) does that. For such a
  statement the statement kind (INSERT / UPDATE / DELETE / MERGE) and the client's own text (no
  `RETURNING`) decide. Text that does not parse stays a query.
- **The ad-hoc path.** The ticket is put **before** the execution, so a full ticket map refuses before
  anything is written, and a failed execution takes its ticket back.
- **The prepared path.** GetFlightInfo does not execute while declared parameters are unbound; it
  answers the schema, as before. A kept result is dropped when new parameters bind or a DoPut executes.
- **Zero-column parameters.** Arrow's JDBC sends a parameter batch with **no columns** for a
  statement without parameters executed through DoPut. The empty dataset schema routes every
  parameterless DML there, so `ParamRowsFrom` now reads a zero-column batch as "no parameters, one
  execution". The spike's re-run found the gap.
- **Verified on real clients** (the spike environment, 2026-10-09):
  - **Python ADBC.**
    - `execute` (unfetched INSERT / UPDATE / DELETE, parameterized), fetched once, `executemany`,
      `adbc_ingest`, errors at execute, manual commit/rollback without fetches.
    - An unfetched `RETURNING` still writes nothing, because it returns rows (documented).
  - **JDBC.**
    - `Statement.execute/executeUpdate`, `prepareStatement` + `execute/executeUpdate`, and
      `CREATE`/`DROP` through `executeUpdate` all write.
    - `executeQuery(INSERT)` writes, then throws "did not return a result set" (documented).
  - **Spark.** `executeBatch` append and reads: unchanged.
  - **dbt over quack.** Unchanged.
- **Not changed here** (the lineage follow-up spec): one lineage run per parameter row of a DoPut
  batch, Flight ingest with no lineage, and a rolled-back statement that still reports `RUN_COMPLETE`.

## Follow-ups

- `is_update` in the prepared-statement result once the Arrow pin carries the field.
- An issue in arrow-adbc: DBAPI `execute` could take `execute_update` when the server announced an
  update. Posted only on the owner's word.
