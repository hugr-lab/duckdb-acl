# Spec 070: the Flight door streams - results out, ingest in, and a client that stops is heard

- **Status**: draft
- **Date**: 2026-09-08
- **Author**: hugr-lab

## Summary

The Flight door materializes every result twice before a client sees a byte - duckdb's own
collection under `Execute(values, false)`, then every chunk converted into a vector of Arrow batches
(`StreamRows`) - and does both under the session connection's execution lock. A client that reads
the first batch of a large result and stops (a LIMIT the client applies, a closed cursor, a dropped
connection) changes nothing: the node keeps computing the whole result, holds it in RAM, and only
then finds nobody listening. This spec makes the result a **stream**: duckdb executes lazily
(`StreamQueryResult`), one chunk becomes one Arrow batch as gRPC pulls it, and the stream's end -
consumed, cancelled, or superseded - **interrupts** the query, exactly as duckdb's own LIMIT stops
a pipeline the moment the consumer stops pulling. The reverse direction, ingest through DoPut, is
already a pull stream (spec 049); what it lacks is the same ear for a client that stops sending,
and the same bounded outcome. Both directions get an audit event and a metric outcome. Memory per
statement becomes a few chunks, whatever the result's size; `acl_max_result_rows` bounds what a
statement may hand out, mirroring `acl_max_ingest_rows`.

## Problem

`DoGetStatement` / `DoGetPreparedStatement` (`src/flight/acl_flight_door.cpp`): `Execute(values,
false)` asks duckdb for a `MaterializedQueryResult` - the whole result in the node's RAM - and
`StreamRows` then converts every chunk into an `arrow::RecordBatch`, so a result of N bytes costs
roughly 2N before the first byte leaves, all of it while `SessionConn::exec` is held. Then
`RecordBatchStream` serves the vector. Three consequences:

1. **RAM is the size of the result.** A `SELECT * FROM big` through the door is a materialization the
   principal chose the size of. Spec 049 bounded the other direction (`acl_max_ingest_rows`, refused
   *while reading*); this one is unbounded.
2. **A client that stops is not heard.** gRPC stops calling `FlightDataStream::Next()` when the
   client cancels the call or closes the reader; duckdb has already finished by then. ADBC's
   `Statement::Cancel`, JDBC's `Statement.cancel()`/`close()`, a `LIMIT` a driver applies client-side,
   a client process that dies - all end in the node computing everything anyway, under the exec lock,
   with the connection unusable for the session's next statement until it is done.
3. **Latency to the first row is the latency of the last.** A dashboard that shows the first page
   waits for the whole scan.

On ingest (`DoPutCommandStatementIngest`) the C stream `IngestGetNext` pulls the gRPC reader batch by
batch into `arrow_scan`, so RAM is bounded and the row cap refuses while reading. What is missing is
the mirror of (2): a client that cancels DoPut mid-stream is seen only as `reader->Next()` failing,
with no event that says what happened, and nothing checks `context.is_cancelled()` between batches;
and a server-side refusal mid-stream (the cap) does not stop the client from sending until the call
is torn down.

quack's door is out of scope: its protocol streams both ways by construction (the result stream and
claim buffer of spec 063's server, `CANCEL_REQUEST`), and the ACL sits at the statement, not in the
transport.

## Design

### Results: a pull stream over `StreamQueryResult`

- `DoGetStatement` and `DoGetPreparedStatement` execute with `allow_stream_result = true` and hand
  gRPC a `flight::RecordBatchStream` over an `arrow::RecordBatchReader` of our own
  (`AclResultReader`): `ReadNext` fetches ONE duckdb chunk (`QueryResult::Fetch`), converts it
  (`ArrowConverter::ToArrowArray` → `ImportRecordBatch`) and returns it. Nothing is buffered beyond
  the chunk in flight; duckdb's pipeline runs as the reader pulls.
- **The reader owns the execution.** It holds the reservation (`shared_ptr<Reservation>`: the
  statement, the session connection) and a `std::unique_lock` on `SessionConn::exec` for its whole
  life - a `StreamQueryResult` is bound to the connection's active query, and duckdb invalidates it
  the moment another query starts on that connection, so the lock is what keeps "one statement at a
  time per connection" true across the stream. The lock is released when the reader is destroyed.
- **The end of the stream interrupts the query.** Three ways a stream ends, one mechanism:
  - *consumed*: `Fetch` returns null; the reader reports end of stream, the result is closed, the
    lock released;
  - *cancelled*: the client cancels the call or closes the reader early (a LIMIT it applied, a
    cursor closed, a process gone). gRPC stops pulling and destroys the `FlightDataStream`; the
    reader's destructor runs with the query still active → `ClientContext::Interrupt()` on the
    session connection, the `StreamQueryResult` is destroyed (duckdb tears the pipeline down), the
    lock is released. Between batches the reader also polls `ServerCallContext::is_cancelled()` and
    ends the stream itself rather than compute one more chunk for nobody;
  - *superseded*: a new statement of the same session arrives (GetFlightInfo / DoPut / ...) while
    a stream is open on its connection. The newer statement takes the exec lock only when the older
    stream is gone; to keep a client that forgot a cursor from hanging its own session, the door
    interrupts an open stream that has not been pulled for `acl_flight_stream_idle` seconds
    (default 30) before the new statement waits on the lock - duckdb's own rule ("a new query
    invalidates the previous stream result"), made explicit and bounded. A driver that pulls
    sequentially never sees this.
- **`acl_max_result_rows`** (GLOBAL, default 0 = unlimited): rows a statement may hand out through
  the door; counted as they are streamed, and the stream ends in a refusal
  (`acl: the result exceeds acl_max_result_rows (N)`) the moment the count passes it - after N rows
  have gone out, which the spec accepts: the bound is about the node's egress and the source's
  work, not about hiding row N+1. The mirror of `acl_max_ingest_rows`.
- **The schema is unchanged**: GetFlightInfo already answers it from the bound statement; the
  stream's `GetSchemaPayload` is the same schema, so a client sees exactly what it saw.
- Transactions (spec 055): a stream inside a client's explicit transaction runs on the session
  connection like today; an interrupted statement inside a transaction leaves the transaction
  invalid, as duckdb does, and the client's next statement gets duckdb's own "transaction is
  aborted" until it rolls back - the same as an interrupted statement on any connection.

### Ingest: the client that stops sending is heard

- `IngestGetNext` checks `context.is_cancelled()` before every `reader->Next()`: a cancelled DoPut
  ends the scan with `acl: the client cancelled the ingest`, which fails the INSERT, which rolls the
  load back - spec 049's "one batch, one outcome" unchanged, now with a name for it.
- A server-side refusal mid-stream (the row cap, a policy `error()` on a row) already fails the
  INSERT and rolls back; the DoPut answer carries it, which is what makes the client stop. Nothing
  new there beyond the event.

### Audit and metrics (spec 069)

- A `door` event per stream end with `detail` ∈ {`stream_consumed`, `stream_cancelled`,
  `stream_superseded`, `stream_capped`} and `rows` = what went out; a `door` event
  `ingest_cancelled` when a DoPut is cancelled by its client. Counted as
  `acl.door.streams{door, outcome}` (a new counter beside `acl.door.tickets`). A cancelled load's
  ingest event is `verdict = denied, reason_code = unavailable` - the taxonomy does not grow by a
  message, and "the client was not there to finish it" is what `unavailable` names; the `door`
  event `ingest_cancelled` beside it says which side stopped.
- A gauge `acl.door.streams_open{door}`: streams currently pulling - the number of session
  connections held by a reader - so an operator sees a fleet of forgotten cursors.

### Data structures

- `FlightDoorState::Reservation` gains nothing; the reader holds it.
- `SessionConn` gains `std::atomic<int64_t> stream_last_pull` (the idle clock) and
  `std::atomic<bool> stream_open`, read by the supersede rule and the gauge.
- Settings `acl_max_result_rows` (BIGINT, 0), `acl_flight_stream_idle` (BIGINT seconds, 30).

### Interaction

- Spec 047's tickets: unchanged - single-use, owner-checked; the reservation's lifetime now extends
  to the stream's end instead of the materialization's.
- Spec 050's sessions: a per-call session (no cookie) gets a per-call connection, which the reader
  keeps alive until the stream ends - as the reservation already did for the ticket.
- Spec 066's drain: `acl_session_kill` on a session with an open stream destroys the connection
  after interrupting it; the client's stream ends in an error, as a killed session's statements do.

## Enforcement & security

- Nothing about *what* a statement returns changes: the statement was parsed, rewritten and bound
  at GetFlightInfo (spec 047) and is executed as bound. Streaming changes when the rows are
  computed, not which.
- The exec lock held for the stream's life is the invariant that keeps a `StreamQueryResult` from
  ever reading another statement's connection state: one statement per connection, enforced by the
  lock, whichever RPC asks. A reader that outlives its call cannot exist - gRPC destroys the
  `FlightDataStream` with the call.
- The interrupt is the session connection's own (`ClientContext::Interrupt`), reached only through
  a reader that owns that connection's lock: no path interrupts another session's query.
- `acl_max_result_rows` is a GLOBAL setting; a principal cannot raise it (spec 068's gate).
- A stream that fails mid-way (a source error at chunk k) ends in a Flight error carrying our
  prefix; the batches already sent are the client's - a partial result is an error, never a silent
  end of stream (`RecordBatchReader` returns the status, `RecordBatchStream` propagates it).
- Fail-closed on cancellation: a cancelled DoPut never commits; a cancelled DoGet never leaves a
  query running after the reader is gone (the destructor interrupts before releasing the lock, and
  the supersede rule bounds a forgotten one).

## Testing

- **C++ (`make test-cpp`, flight build)**: `test_acl_flight_stream.cpp` with an in-process
  `arrow::flight::sql::FlightSqlClient` against `acl_flight_serve` on loopback:
  - *first batch before the last*: `SELECT i FROM range(200000000)`; the first batch arrives in
    well under the time the whole scan takes (measured: the reader is pulled once, timed);
  - *cancel is heard*: read one batch, close the reader; within a second the session's next
    statement runs (the lock was released) and `acl_audit_events()` has a `door` event
    `stream_cancelled` with `rows` = the batch's size; `acl.door.streams{outcome=cancelled}` = 1;
  - *supersede*: open a stream, do not pull, send the next statement with `acl_flight_stream_idle`
    = 1: it runs; the old stream's event is `stream_superseded`;
  - *cap*: `SET GLOBAL acl_max_result_rows = 1000`, a 5000-row result ends in the refusal after the
    cap, event `stream_capped`, the client sees `acl: the result exceeds acl_max_result_rows (1000)`;
  - *consumed*: a full read ends with `stream_consumed` and `rows` = the count;
  - *a source error mid-stream* (a table function that throws at row k) reaches the client as an
    error, not a short result;
  - *ingest cancel*: a DoPut of 1M rows cancelled after the first batch: the target has none of
    them (rollback), event `ingest_cancelled`, the ingest event `denied / unavailable`.
- **e2e (`make test-flight`)**: `adbc_client.py` gains a LIMIT-shaped read (fetch one batch of a
  large result, close) and asserts the server's next statement on the same connection is prompt;
  `client.py` the ingest cancel.
- The memory claim is pinned by construction (no vector of batches exists in the code) and by
  the first-batch timing; an RSS measurement is a bench (`test/bench/`), not a test.

## Alternatives considered

- **Keep materializing, bound it** (`acl_max_result_rows` alone): bounds the damage, keeps the
  latency and the deaf ear; rejected - the cap stays, as the second line.
- **Materialize to Arrow batches lazily but keep duckdb's collection**: halves the RAM, keeps the
  rest; rejected.
- **`DoExchange`** for a bidirectional stream with explicit flow control: the protocol has it, no
  driver we serve (ADBC, JDBC) speaks it for queries; a follow-up if ever.
- **Cancel through `CancelFlightInfo`/`CancelQuery` actions** (Flight SQL 13+): additive - a
  client that sends it gets the same interrupt; the stream's end must work without it, because
  most clients just close.

## Follow-ups

- `CancelFlightInfo` / `CancelQuery` handlers (Flight SQL 13+): map to the same interrupt, so a
  driver that cancels explicitly is answered rather than just ignored.
- The quack door's result cap: `acl_max_result_rows` applies only to the Flight door here; quack's
  own result stream would need the count at the statement driver (the `sync.py` hook site).
- Back-pressure across the fleet (a node with too many open streams refuses new tickets) belongs
  with spec 066's drain and the orchestrator, not here.
