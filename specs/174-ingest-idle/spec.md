# Spec 174: a Flight ingest whose client goes silent lets its session go

- **Status**: implemented
- **Date**: 2026-11-19
- **Author**: the owner asked for it (2026-11-19), after acl-clients spec 009's review found the client-side half

## Summary

A Flight `DoPut` ingest holds its session's lock and its own transaction while it reads the client's stream. A
client that stops sending without ending the call held both for as long as it stayed silent. Now the wait for the
next batch has a limit, `acl_flight_ingest_idle` (300 s; `0` = none), and an operator's `KILL SESSION` ends it at
once: the load rolls back and the session's next statement runs.

## Problem

`DoPutCommandStatementIngest` takes `LockForStatement` and runs the composed INSERT / MERGE / DELETE, whose
`arrow_scan` pulls the client's stream through `IngestGetNext` → Arrow's `FlightMessageReader::Next()`. `Next()`
blocks until the client sends a batch, half-closes or the call dies; `is_cancelled()` was asked only between
batches. A client that sent a batch and then nothing - a driver that rethrew a broken source without cancelling
(acl-clients spec 009's review: Arrow Java's `executeIngest` does exactly that), a producer that hangs, a process
that stops - kept:

- the session's `exec` lock: every later statement of that session waited (measured: the next `SELECT` behind a
  silent load waited for as long as the client held the call);
- its transaction open, and its handler thread;
- `KILL SESSION` could not end it: nothing woke the read.

A dead peer without a reset (a partition) is the same until gRPC's own keepalive gives up.

Flight's API has no way to interrupt `Next()` (`ServerCallContext` offers `is_cancelled()` only, not gRPC's
`TryCancel`), and `acl_flight_stream_idle` (spec 070) is the other direction - a result the client does not pull,
ended from the next statement's thread between pulls.

## Design

- **The stream is read on a thread of its own** (`IngestPump`): from the statement's execution on, one thread calls
  `Next()` when asked and hands back its answer; `IngestNextChunk` waits for it in 200 ms steps, and at each step
  asks whether the call was cancelled, the session is still alive (`SessionAlive` - no bump), and how long it has
  waited. Each batch received is the session's activity (`SessionTouch`): a load longer than
  `acl_session_idle_timeout` never idles its session out under it.
- **A wait that ends without a batch fails the load**: past `acl_flight_ingest_idle` seconds
  (`acl: the ingest stream sent nothing for N s (acl_flight_ingest_idle)`) or when the session ended
  (`acl: the session ended during the ingest`). The scan fails, the handler rolls back, audits a `door` event
  `ingest_idle` / `ingest_session_ended` and an `ingest` event `denied` / `unavailable` (spec 070's taxonomy for a
  load its client was not there to finish), and returns `Cancelled`. Every other scan thread that asks once more is
  answered at once (duckdb reads the stream from many threads: each waited the limit again - 16 threads, 32 s - the
  e2e's first run).
- **The session goes before the read does**: the pump lives in the ingest's state, declared before the session's
  lock, so the lock is released (the session free) before the pump's thread is joined; that join waits for `Next()`
  to return - when the client sends, cancels or goes away. A silent client keeps its call and its handler thread,
  never its session.
- **`acl_flight_ingest_idle`** (GLOBAL, BIGINT, 300): long enough for a producer that computes between batches
  (a Spark stage); `0` = no limit, the kill still ends the wait.

## Enforcement & security

Nothing is admitted that was refused: the change only ends a load sooner, always by rollback (one batch, one
outcome - spec 049). A load cut by the limit or the kill writes nothing; its rows are never committed. The
reader is read by one thread at a time (the pump; before it starts nothing reads). The handler's frame - the reader,
the call - outlives the pump's thread (joined in the state's destructor), so a read never runs on a finished call.
No new SQL surface, no parameters.

## Tests

- e2e `test/e2e/flight/stream.sh` (`stream_client.py stall`): one batch, then silence with the call open -
  - with `acl_flight_ingest_idle = 2` the session's next statement runs within seconds (it waited for the
    client before), the load's rows are not there, one `ingest_idle` event;
  - with `0` the operator's `acl_session_kill` ends the waiting load (`ingest_session_ended`), nothing stored.
- The existing ingest cases (spec 049 / 051 / 070 / 173: run.sh, the client that dies mid-load) pass unchanged.

## Alternatives considered

- **gRPC's `TryCancel` through a server interceptor**: Arrow installs its own interceptors for its middleware, and
  a second `SetInterceptorCreators` replaces them; no seam reaches the call's `ServerContext`.
- **Keepalive only** (`GRPC_ARG_KEEPALIVE_TIME_MS` on the server builder): ends a dead peer's call sooner, not an
  alive client's silence. A follow-up if partitions show up in practice; with this spec they no longer hold a
  session, only a handler thread until gRPC's default keepalive (2 h).
- **A limit on the whole load**: punishes a big load that is progressing; the limit here is on silence.
