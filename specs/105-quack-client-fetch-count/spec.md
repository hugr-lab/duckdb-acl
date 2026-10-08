# Spec 105: the quack client ends a stream one batch short - patch it until upstream does

- **Status**: implemented
- **Date**: 2026-10-08
- **Found by**: CI on main 6ddc3a4 (run 37623165013, linux_amd64).
  `test/sql/integration/acl_quack_fetch_window.test:152` failed with `IO Error: Quack stream ended
  with 133 of 134 batches received`. Before that the test had been stable since spec 077.

## Problem

The quack client (`src/quack_fetch_ahead.cpp`, quack 974927a, and the same on quack's main) keeps up to
`quack_fetch_read_ahead` FETCH requests in flight.

`QuackFetcher::TopUp` claims an index (`next_request++`), encodes the request, and only then counts it
in flight (`++in_flight`). `FinishTask` ends the stream when the counter reaches 0 after a terminal
answer, and checks the pushed batches against the total the server announced.

The race:

1. Thread A claims the last index that carries data, k, and is preempted before it counts it.
2. Thread C claims k+1, past the end, and sends it. The server answers with a terminal response that
   announces k+1 batches.
3. C's `FinishTask` sees `in_flight == 0`, because A's request is not counted yet. It finishes the
   buffer with k pushed batches against k+1 announced.
4. A then sends FETCH k. The server answers it, but the batch is dropped because the buffer has
   already finished.

The batch that goes missing is always the last one with data. The race needs oversubscribed CPUs: CI
has 4 cores, and here it took 12 to 24 parallel copies on a 16-core machine.

It is not our server, and spec 077's window has nothing to do with it:

- it reproduces with the window off (`acl_quack_fetch_window = 0`), where `AclFetchWindowPlan`
  answers every FETCH with its batch;
- in the quack logs of three failing streams, every FETCH got a `FETCH_RESPONSE` and there is no
  `ERROR_RESPONSE`;
- it reproduces on duckdb 4fbae43 too (spec 104's build: 4 failures in 36 stress runs).

## Design

- `patches/quack/0001-count-fetch-in-flight-before-claim.patch`: `++in_flight` moves before the
  index is claimed. A claimed index is then always counted, so the counter cannot reach 0 while a
  claimed request is still unsent.
- `extension_config.cmake` applies `patches/quack/*.patch` to the client's clone after duckdb's own
  patches (`APPLY_PATCHES` reads only duckdb's directory). duckdb's patch script refuses a clone that
  carries changes beyond its own patches ("Detected local changes"), and it re-runs whenever
  FetchContent re-populates. So our patches come OFF before `duckdb_extension_load(quack)` (a
  reverse `git apply`, only where `--reverse --check` says they are in) and go back ON after it. This
  was checked with duckdb's patch step forced to re-run (its stamp removed).
- A local checkout (`DUCKDB_QUACK_DIRECTORY`, `DUCKDB_NEW_EXTENSION_BUILD`) is the developer's own
  tree. It is left alone, with a warning.
- The embedded server (`third_party/quack`, `sync.py`) does not compile the fetcher, so the patch
  touches only the loadable client.
- The patch leaves when quack takes the fix. The issue for quack carries the same diff.

## Testing

**Deterministic A/B.** A probe made the race wide:

- the probe sleeps 50 ms after the claim, on odd indices, in a scratch build of the client;
- the probe is not part of the patch.

Read `SELECT i FROM seq ORDER BY i` through the door: 8 parallel copies, 60 reads each, half of them
with the window off.

| Client | Files passed | Batch-count errors |
|---|---|---|
| Unpatched + probe | 0 of 8 | 8 ("77..90 of 86..98 batches"), on the first read of each |
| Patched + probe | 8 of 8 | 0, in 480 reads |

**Without the probe.**

- 12 parallel copies × 60 reads with the patch: 0 errors.
- `make test-integration`: green (390 assertions).
- The whole gate is green as well.

The regression test belongs upstream: a debug sleep between the claim and the count, beside quack's
existing `quack_debug_fetch_delay_ms`. With it, a full read of a multi-batch result fails at once
without the fix.

## Not here

Under the same overload (24 copies), most reads end in `Timeout was reached error for HTTP POST` to
the local door instead. That is a separate symptom, not investigated in this spec.
