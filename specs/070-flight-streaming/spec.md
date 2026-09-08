# Spec 070: the Flight door streams - results out, ingest in, and a client that stops is heard

- **Status**: implemented
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
- **The result lives in a slot the reader and the connection share** (`FlightDoorState::ResultStream`:
  the `StreamQueryResult` and a `superseded` mark; `SessionConn::stream` points at the current one).
  A reader lives as long as its gRPC call, which a client that forgot its cursor never ends, so the
  execution lock cannot be the reader's for the stream's life: instead **every pull takes
  `SessionConn::exec` + `stream_lock` and releases them** - a statement of the session never runs in
  the middle of a pull (duckdb invalidates a `StreamQueryResult` the moment another query starts on
  its connection), and the session's next statement can end the stream from its own thread. Every
  place a statement used to take `exec` now goes through `LockForStatement`: it takes `exec`, and if a
  stream is open on the connection either ends it (idle past `acl_flight_stream_idle` since its last
  pull *returned*: interrupt, close, drop the result, mark the slot superseded) or lets go and looks
  again 20 ms later (the stream is being pulled). `acl_flight_stream_idle = 0` turns the rule off -
  the statement waits for the stream's own end. The slot is the stream's own, so a newer stream on
  the same connection never overwrites what an older reader will read about itself.
- **Ending a stream closes the query, not only interrupts it** (`SessionConn::CloseResult`). At our
  pin `~StreamQueryResult` releases nothing; `StreamQueryResult::Close()` is what runs duckdb's
  `CleanupInternal` - `CancelTasks` and the release of the active query, the executor and every
  operator's intermediate state (a sort's runs, a hash table). Interrupt alone would stop the CPU
  and leave that memory on the connection until the session's next statement, which a client
  holding an idle cookie never sends. Every end - the reader's, the supersede, the sweep - goes
  through it.
- **A pull is the session's activity, and a dead session ends its stream.** Each pull of a durable
  (cookie) session calls `PolicyStore::SessionTouch` - `SessionAlive`'s judgements plus the idle
  bump, so a client that pulls a long stream and sends no other RPC is not reaped under it - and a
  session that is gone (killed by `acl_session_kill`, expired) ends the stream at that pull:
  `acl: the session ended`, recorded as `stream_superseded`. A per-call (cookie-less) session is
  closed at its RPC's end by design, so its stream is the reader's alone and is not judged. Between
  pulls a killed session's stream is ended by the door's sweep (`ConnFor`, once a minute, on any
  session's RPC) - outside the door's lock, since ending it waits for a pull in flight and for the
  query's tasks.
- **One `ClientProperties` snapshot** (taken under `exec` when the statement executes) builds both
  the schema and every batch: the layout-affecting GLOBAL arrow settings (`arrow_large_buffer_size`,
  string views, list views) may change while a stream lives, and the two must agree; a per-pull
  read would also race a `SET` of the session's own (spec 068) on the same config.
- **The end of the stream interrupts the query.** Five ways a stream ends, one mechanism
  (`AclResultReader::End`, once per stream: interrupt unless consumed, drop the result, one event):
  - *consumed*: `Fetch` returns an empty chunk; the reader reports end of stream, the result is
    closed;
  - *cancelled*: the client cancels the call or closes the reader early (a LIMIT it applied, a
    cursor closed, a process gone). gRPC stops pulling and destroys the `FlightDataStream`; the
    reader's destructor runs with the query still active → `ClientContext::Interrupt()` on the
    session connection, the `StreamQueryResult` is destroyed (duckdb tears the pipeline down).
    Between batches the reader also polls `ServerCallContext::is_cancelled()` and ends the stream
    itself rather than compute one more chunk for nobody;
  - *superseded*: a new statement of the same session arrives (GetFlightInfo / DoPut / ...) while
    a stream is open on its connection and unpulled for `acl_flight_stream_idle` seconds (default
    30): the statement ends it and runs - duckdb's own rule ("a new query invalidates the previous
    stream result"), made explicit and bounded. A driver that pulls sequentially never sees this; a
    statement arriving while the stream is being pulled waits for it. The reader learns of it at
    its next pull (a `Cancelled` status carrying `acl: the stream was superseded by the session's
    next statement`) or in its destructor, and records `stream_superseded` either way. A session
    that dies with a stream open (`SweepConnsLocked`) ends it the same way;
  - *capped* and *failed*: below.
- **`acl_max_result_rows`** (GLOBAL, default 0 = unlimited): rows a statement may hand out through
  the door. Exactly N go out - the batch that crosses the line is cut at it (`DataChunk::
  SetCardinality`) - and the next pull is the refusal (`acl: the result exceeds acl_max_result_rows
  (N)`), so the event's `rows` is what the client received. The bound is about the node's egress
  and the source's work, not about hiding row N+1 - the refusal names the cap. The mirror of
  `acl_max_ingest_rows`.
- **The schema is unchanged**: GetFlightInfo already answers it from the bound statement; the
  stream's `GetSchemaPayload` is the same schema, so a client sees exactly what it saw.
- Transactions (spec 055): a stream inside a client's explicit transaction runs on the session
  connection like today. An interrupted stream does NOT invalidate the transaction: duckdb's cleanup
  of an abandoned stream result passes `invalidate_transaction = false` (`client_context.cpp`,
  `CleanupInternal`), and only SELECTs stream (DML binds `FORCE_MATERIALIZED`), so no partial write
  can survive to a COMMIT. The client's transaction stays usable after a cancelled read.

### Ingest: the client that stops sending is heard

- `IngestGetNext` checks `context.is_cancelled()` before every `reader->Next()`, after a failed one,
  and **at the end of the stream**: a client that died mid-load reads as a clean end of stream (gRPC's
  `Read` returns false for a torn-down call exactly as for a half-close), and only the call's
  cancelled flag tells a finished load from a dead sender - committing what arrived before the death
  would make a partial load. A cancelled DoPut ends the scan with `acl: the client cancelled the
  ingest`, which fails the INSERT, which rolls the load back - spec 049's "one batch, one outcome"
  unchanged, now with a name for it.
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

- `FlightDoorState::Reservation` gains nothing; the reader holds it (the statement and the session
  connection stay alive as long as the stream).
- `FlightDoorState::ResultStream` (the slot: `unique_ptr<QueryResult> result`, `bool superseded`);
  `SessionConn` gains `std::mutex stream_lock`, `shared_ptr<ResultStream> stream`,
  `std::atomic<int64_t> stream_last_pull` (the idle clock, steady-clock milliseconds, stamped when a
  pull returns), `EndStreamLocked()` and `CloseResult()`; `FlightDoorState` gains
  `LockForStatement(conn)`, a `SweepConnsLocked` that hands the reaped connections back for their
  streams to be ended outside the lock, and the `open_streams` counter behind the gauge.
  `AclResultReader` carries the properties snapshot, `durable` (a cookie session: judged per pull),
  `cap_reached` (the refusal is the pull after the cut batch) and `Abandon()` (the stream wrapper's
  allocation threw under the caller's `exec`: the reader must not take it in its destructor).
- `PolicyStore::SessionTouch(handle)`: `SessionAlive` plus the idle bump.
- Settings `acl_max_result_rows` (BIGINT, 0), `acl_flight_stream_idle` (BIGINT seconds, 30; 0 =
  off); `PolicyStore::MaxResultRows()` / `FlightStreamIdleSeconds()` read them through the instance.

### Interaction

- Spec 047's tickets: unchanged - single-use, owner-checked; the reservation's lifetime now extends
  to the stream's end instead of the materialization's.
- Spec 050's sessions: a per-call session (no cookie) gets a per-call connection, which the reader
  keeps alive until the stream ends - as the reservation already did for the ticket.
- Spec 066's drain: `acl_session_kill` on a session with an open stream ends the stream at its next
  pull (`acl: the session ended`) or at the door's next sweep, whichever comes first; the reader
  pins the connection until then, and the connection goes with the reader. `acl_flight_stop` joins
  the server's handler threads, so a stream that keeps pulling holds the stop until it is ended -
  kill first, as spec 066's runbook says.

## Enforcement & security

- Nothing about *what* a statement returns changes: the statement was parsed, rewritten and bound
  at GetFlightInfo (spec 047) and is executed as bound. Streaming changes when the rows are
  computed, not which.
- `exec` taken per pull and by every statement (`LockForStatement`) is the invariant that keeps a
  `StreamQueryResult` from ever reading another statement's connection state: one statement per
  connection at any instant, whichever RPC asks, and a stream is ended before a statement runs on
  its connection - never invalidated underneath a pull. A reader that outlives its call cannot
  exist - gRPC destroys the `FlightDataStream` with the call.
- The interrupt is the session connection's own (`ClientContext::Interrupt`), reached only through
  that connection's reader, a statement of the same session holding its `exec`, or the sweep of a
  dead session: no path interrupts another session's query.
- `acl_max_result_rows` is a GLOBAL setting; a principal cannot raise it (spec 068's gate).
- A stream that fails mid-way (a source error at chunk k) ends in a Flight error carrying our
  prefix; the batches already sent are the client's - a partial result is an error, never a silent
  end of stream (`RecordBatchReader` returns the status, `RecordBatchStream` propagates it).
- Fail-closed on cancellation: a cancelled DoPut never commits; a cancelled DoGet never leaves a
  query running after the reader is gone (the destructor interrupts before releasing the lock, and
  the supersede rule bounds a forgotten one).

## Testing

- **e2e (`make test-flight`, `test/e2e/flight/stream.sh` + `stream_client.py`)**: a third-party
  pyarrow Flight client against the served node (a duckdb CLI fed through a fifo, whose own stdin
  answers what the server heard - `acl_audit_events()`), over a virtual view of 200M rows nobody
  stores (`range(200000000)` with a cast per row - a materialization would take seconds and
  gigabytes):
  - *first batch before the last*: `SELECT * FROM big`, the first `read_chunk` within 3 s (measured
    ~30 ms), then `reader.cancel()`; the last `door` event is `stream_cancelled` with rows > 0 - the
    cancel was heard and the query interrupted;
  - *consumed*: the tenant's five rows end as `stream_consumed,5`;
  - *supersede*: read one batch, keep the reader open and unpulled, run `SELECT 1` on the same
    session (a cookie; warmed up first, since the cookie arrives with the first answer) with
    `acl_flight_stream_idle = 2`: it answers after ≥ 1.5 s and < 10 s, and one `stream_superseded`
    event lands once gRPC tears the old call down;
  - *killed*: read one batch, pause; the server kills every live session (`acl_session_kill` over
    `acl_sessions()`); the client drains what gRPC had already sent ahead (the door pulls a few
    batches past the one the client reads - the same reason `stream_cancelled` records more rows
    than the client took) and then fails with `acl: the session ended`; the newest stream event is
    `stream_superseded` with rows > 0;
  - *cap*: `SET GLOBAL acl_max_result_rows = 1000` (confirmed through `current_setting` before the
    client starts - a cap not in force would mean a 200M-row read); the client receives exactly
    1000 rows and then `acl: the result exceeds acl_max_result_rows (1000)`, event `stream_capped`
    with rows = 1000;
  - *ingest cancel*: a DoPut streaming 10k-row batches forever, `kill -9` after 30k sent: one
    `door` event `ingest_cancelled`, zero of its rows stored, the ingest event `denied / unavailable`.
  Every stream event is awaited (it lands when gRPC tears the call down, a moment after the client is
  gone); the client carries its own deadline (`signal.alarm`, 120 s) so a hang fails the run.
- A source error mid-stream reaches the client as an error, not a short result, by construction
  (`RecordBatchReader::ReadNext` returns the status; `RecordBatchStream` propagates it); the
  existing Flight e2e and the C++ door tests keep every other RPC where it was.
- Not covered by a test, stated so it is not mistaken for tested: the "waits while being pulled"
  branch of `LockForStatement` (only the idle branch runs in the e2e); the `is_cancelled()` poll
  between pulls (indistinguishable from the destructor path from outside); `stream_failed` end to
  end (no source fails mid-stream on demand in the fixture); the transaction interaction; the
  counter and gauge through `acl_metrics()` (their derivation is spec 069's, from the same events
  the e2e reads).
- The memory claim is pinned by construction (no vector of batches exists in the code) and by
  the first-batch timing; an RSS measurement is a bench (`test/bench/`), not a test.

## Found on the way

- **The CI's e2e steps could not fail.** `make test-flight 2>&1 | tee flight.log` under GitHub's
  default `bash -e` (no pipefail) reported tee's exit code; `assert_ran.sh flight.log 0 0` checked
  only for `SKIP:` lines. The Flight e2e had been red on main since the spec 069 review (#117,
  2026-09-04) - `SessionOpen` now swallows a verification failure into a `session refused` event and
  the door answers `authentication failed`, which the run.sh check from the 046 review (the keys
  *could not be read* in the client's refusal) contradicted - and every run was green. Fixed here:
  `defaults: run: shell: bash` (= `bash -eo pipefail`) for the whole workflow, `assert_ran.sh`
  fails on a `FAIL:` line too, and the check asserts spec 069's contract: the client gets the named
  refusal and no reason, the audit gets the reason (`source_error`, the text).
- **A dead ingest client reads as a clean end of stream.** gRPC's `Read` returns false for a
  torn-down call exactly as for a half-close, so without the `is_cancelled()` check at end of stream
  the load of a client killed mid-way was *committed* - a partial load nobody asked for. The
  end-of-stream check is what turns it into the rollback.
- **The idle clock in whole seconds** made a 2 s threshold fire after 1.2 s; the clock is
  steady-clock milliseconds - and stamped when a pull returns, not when it starts: a chunk that
  takes longer than the idle rule to compute (a big sort's first chunk) followed by any RPC of the
  same session had been superseded while being pulled (review).
- **Interrupt alone leaks the query** (review): `~StreamQueryResult` is empty at our pin, `Close()`
  is what releases the executor and the operators' state - every end now closes.
- **The cap over-counted** (review): the batch that crossed the cap was refused *and* counted, so
  a cap of 1000 sent nothing and recorded 2048. The batch is cut at the line, the refusal follows.
- **A killed session's stream ran on** (review): nothing judged the session between pulls, and a
  stream pulled for longer than the idle timeout without another RPC was reaped under its client.
  `SessionTouch` per pull settles both.
- **Schema and batches from different properties** (review): the schema came from a fresh
  connection at execute, each batch from the session connection at pull time; one snapshot now.

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
