# Spec 077: the quack door's fetch window

- **Status**: implemented
- **Date**: 2026-09-22
- **Author**: hugr-lab

## Summary

A quack client keeps its whole read-ahead of FETCHes in flight and, when its query stops early (a
`LIMIT` met, a cursor closed), waits for every one of them before it cancels. One `LIMIT 1` therefore
costs the server that many full batches (duckdb-quack #277). The protocol gives a server no way to
ask for fewer, so the embedded door answers within it. Past `acl_quack_fetch_window` batches with
rows above the client's ack, a FETCH is answered at once with an **empty batch**: one chunk of zero
rows, which the client's scan skips. The produced batches move to the indices after it. The client
still reads every row once, in order, and its own check of the batch count still holds. The window
starts small and doubles while the client keeps reading, up to `acl_quack_fetch_window_max`. An early
stop costs the window a result starts with, not the read-ahead. A long read reaches full speed within
a few windows. This is a stopgap until the client stops early by itself (#277, and the
server-announced read-ahead suggested there).

## Problem

Spec 063's measurement: a quack client asks 64 FETCHes ahead (`quack_fetch_read_ahead` 0 = its async
threads). On `LIMIT 1` over a large result it pulls 64 batches before its CANCEL. At quack's 32 MiB
batch that is 2.4 s, +2.3 GiB on the server and 7.9 GiB on the client. Spec 063 lowered the embed's
batch to 8 MiB, which makes the same stop 0.66 s and +0.5 GiB, and left it there until #277 is fixed.
The batch size is a blunt lever: it trades every full read's efficiency for the early stop's cost,
and still multiplies whatever it is by the client's depth, a number the server does not choose.

What the server cannot do within the protocol, and why the window answers the way it does:

- An empty `FETCH_RESPONSE` without chunks is the end of the stream to the client: a short result,
  or a count mismatch when a total rides along.
- An error fails the query.
- A FETCH held until the client acknowledges more hangs an early stop, because the client waits for
  every outstanding answer before it cancels.

A batch that has chunks with no rows in them is none of those. It is a batch. The client pushes it
into its buffer under its index, counts it, acknowledges it, and its scan skips a chunk of size 0
(`QuackScan`: `if (response_chunk.size() > 0)`).

## Design

- **Settings**, both UBIGINT and GLOBAL (the server reads them from the instance):
  - `acl_quack_fetch_window` (default **8**) is the batches with rows a client may have above its ack
    when its result starts. `0` turns the window off and gives quack's behaviour exactly: every index
    is its own batch.
  - `acl_quack_fetch_window_max` (default **0**, no cap) is where the window stops growing. It doubles
    each time the client acknowledges a window's worth of batches with rows. Setting both to one value
    gives a fixed window: a hard per-client bound on batches in flight for the whole result.
  - Why the window grows: the client's scan decodes one batch per thread, so the number of batches
    in flight, not their bytes, sets a full read's speed. A fixed window below the client's cores
    halves it (measured below). Growth keeps an early stop cheap without taxing a long read.
- **The plan** (`AclFetchWindowPlan`, header-only in `acl_quack_fetch_window.hpp`) decides each dense
  FETCH index (the client's index plus PREPARE's inline batches) in index order:
  - The index carries the next produced batch while fewer than the window's batches with rows are
    above the highest ack seen.
  - Otherwise it is EMPTY.
  - A FETCH for index `k` decides every index up to `k` at once. The client asks densely, so all of
    them are requested. Which produced batch an index gets never depends on arrival order, so the
    result keeps its order.
- **The terminal answer.** A decision whose produced batch is past the end is the terminal, and its
  total is the produced count plus the empties. From the first terminal on, the plan is *closed*: no
  index is made empty after a total has been announced, so every terminal announces the same total.
  Empties before it are all requested, so all are received, and the client's check (batches received
  equal the total) passes.
- **Retries and caches.** An empty answer is kept in the stream's `served` map like any payload, so
  an HTTP retry of that index gets the same empty batch. A result cache (reconnects) retains it with
  the rest. An index at or below the ack is GONE; no correct client asks for it, and the answer is an
  error instead of quack's wait.
- **Where it lives.** A window per result stream, in a `ClientContextState` on the session's server
  connection, found by stream identity: a superseded stream's FETCH can still be in its handler. The
  FETCH handler asks the plan through a `sync.py` patch of the generated server (four small hunks).
  The retry path, the pop, the header and the retain stay quack's. The empty batch is serialized once
  per stream, with quack's wire options. Those options are file-static in quack, so acl repeats them,
  and `sync.py` fails if quack's definition changes (`PRISTINE_GUARDS`).
- **The hold** (addendum of 2026-09-23). An empty answer is held while a batch with rows below it
  is not yet acknowledged. The client's scan threads each claim their own index. Without the hold,
  a thread holding an empty index consumes it, frees its slot and asks again. With the ack stuck
  below a batch still on its way, every new index is empty too, so the client spins FETCHes for as
  long as that batch takes. A sort before its first batch can take seconds, and past `MAX_AHEAD` the
  query fails. Two holds, neither waiting on the client alone:
  - **Production.** A batch with rows below is not yet answered, and its own FETCH has arrived. The
    empty answer waits for any pop of the stream's buffer, so it is released by the server's own
    progress. After the producer is done, it polls instead, because a finished buffer wakes nobody.
    If a batch below has not been requested here yet, the hold is on the timer instead: at the
    connection cap its FETCH may have been shed, and without a timer the empties above it would
    wait for the client's 30-second read timeout (found by the concurrency bench, below).
  - **Acknowledgement.** The batches below are answered but not acknowledged: in transit, or the
    client stopped. A reading client sends the ack as soon as it consumes the batch. A client that
    stopped early sends nothing more and waits for these answers before it cancels, so the hold
    also ends after a time. The time starts at 20 ms and doubles, up to 500 ms, each time it runs
    out with the ack still stuck (a client starved of CPU). The next ack that moves resets it.
- **What it costs.** Each empty answer is a FETCH round trip carrying a few hundred bytes. Under a
  fixed window W, a client of depth D makes about D / W FETCHes per batch with rows, most of them
  empty. A growing window stops sending empties once it reaches D. An early stop waits up to one
  acknowledgement hold, 20 ms, for the empties past the window.
- **A bound on the work of one FETCH.** The plan decides every index up to the one requested, so a
  FETCH more than 65536 indices above the ack is refused (`TOO_FAR`) before anything is decided.
  Without that limit, one request naming index 10⁹ would make the server decide a billion indices.

## Enforcement & security

Not an enforcement feature: the window changes which index carries which batch, never what a batch
holds. An empty batch carries no row and no value. The window bounds what one client's early stop costs
the server, which is a resource concern, not a leak. A client cannot use the window to read beyond
its result or its own stream. A FETCH for an index the client acknowledged is refused, where quack
would have waited. A FETCH far above the ack is refused before the plan does any work, so one
authenticated request cannot make the server decide an unbounded number of indices.

## Testing

- **C++**, `test/cpp/test_acl_quack_fetch_window.cpp`: a simulated quack client with dense requests,
  a contiguous ack, a slot held until consumption, and an early stop that waits for its in-flight
  FETCHes. The server answers and the network delivers in random orders, 40 seeds times 11 shapes
  (fixed, growing and capped windows, larger or smaller than the depth, inline batches, an empty
  result, one batch). Invariants:
  - every produced batch is read once, in order;
  - received equals the announced total, and every terminal announces the same total;
  - rows in flight never exceed the window in force;
  - `LIMIT 1` receives at most the starting window after the stop, a fixed window bounds a stop in
    the middle of the stream, a capped one bounds it by its cap, and window 0 pulls the read-ahead;
  - a growing window stops the empties, a fixed one keeps them, and growth stops at the cap;
  - with sixteen scan threads and a slow producer, FETCHes stay near read-ahead / window per batch,
    and the same client against a server without the hold spins, 9 to 12 times as many FETCHes;
  - the correctness invariants hold for one or sixteen scan threads, with everything produced at
    once or at a slow pace;
  - a FETCH far above the ack is refused and decides nothing;
  - a shuffled first burst yields the same plan;
  - an acknowledged index is GONE;
  - window 0 is the identity.
- **SQL**, `test/sql/integration/acl_quack_fetch_window.test`: one-chunk batches, a window fixed at 2
  against a read-ahead of 16. It checks:
  - 200k rows arrive complete and in order (the `rowid` lag check);
  - text, NULLs, a list and a struct arrive through the empties;
  - `LIMIT 3`, an empty result and an inline one;
  - a retained result, with reconnects on;
  - a growing window gives the same rows, in order;
  - window 0 gives the same rows.
  - The client's own log counts its FETCHes, so the test shows the empties happened: more than 300
    for about 98 batches under the fixed window, fewer than 200 once the window grows, and fewer
    than 150 without it.
- **Bench**, `test/bench/door_stream.py --set acl_quack_fetch_window=N`: the numbers below.

## Measurements

`test/bench/door_stream.py` on one 16-core macOS arm64 machine, a fresh server per read, the server's
resident set sampled every 100 ms. The first read is `LIMIT 1` over 1B rows. The full read is 300M
rows at the client's full speed. The slow read is 50M rows on one client thread, with a hash per row.

| window | batch | LIMIT 1, 1B rows | full read, 300M rows | slow read, 50M rows |
| --- | --- | --- | --- | --- |
| 0 (quack's behaviour) | 32 MiB | 2.645 s, +2344 MiB | 3.74 s, +217 MiB | 11.0 s, +623 MiB |
| 0 (spec 063's default) | 8 MiB | 0.673 s, +515 MiB | 3.77 s, +58 MiB | 11.0 s, +200 MiB |
| fixed 8 | 8 MiB | 0.126 s, +56 MiB | 8.00 s, +91 MiB | 11.0 s, +344 MiB |
| fixed 8 | 32 MiB | 0.408 s, +371 MiB | 7.79 s, +233 MiB | 11.1 s, +606 MiB |
| fixed 16 | 32 MiB | 0.719 s, +621 MiB | 3.77 s, +218 MiB | 11.0 s, +623 MiB |
| **8, growing** (default) | **8 MiB** | **0.126 s, +55 MiB** | **3.78 s, +65 MiB** | 10.65 s, +409 MiB |
| 8, growing | 32 MiB | 0.408 s, +382 MiB | 3.88 s, +224 MiB | 10.8 s, +609 MiB |

- **The early stop.** With the default, `LIMIT 1` costs 5x less time and 9x less server memory than
  with spec 063's batch alone, and 21x and 42x less than with quack's own settings.
- **The full read.** A fixed window of 8 halves the full read at either batch size, and 16 restores
  it: the client needs about one batch in flight per core. The growing window reaches that by itself.
- **The slow read.** Its server memory goes up at 8 MiB, from +200 to +410 MiB (repeated twice, the
  same). Without a window, the client's read-ahead pulled most of this 50M-row result into client
  memory early. With the window, the result waits on the server, in the producer's buffer, whose
  bound is `acl_quack_fetch_producer_buffer_bytes`. A result larger than the client's read-ahead
  reaches the same bound either way, and at 32 MiB the numbers match.
- **The batch size.** 8 MiB stays the default. Under the window it is at least as good as 32 MiB on
  every read here, with a quarter of the memory. Quack's 32 MiB is meant for fewer round trips on a
  slow network, which this local bench does not model.

**Addendum 2026-09-23: the spin, measured.** Spec 077 shipped without the hold (#152). Under a
saturated CPU (16 busy processes on 16 cores), the first fix held empties only for production. That
still let one read of 98 one-chunk batches take up to 9335 FETCHes, because the holds were bypassed
once the producer had finished, and this small result finishes at once. With both holds, ten loaded
runs stay flat. Counts are FETCHes for about 98 batches:

| window | idle | loaded, 10 runs |
| --- | --- | --- |
| fixed 2 | 725-727 | 642-698 |
| from 2, growing | 163-175 | 136-167 |
| from 8, growing | 131-140 | 110-139 |
| 0 | 95-97 | 95-100 |

`LIMIT 10` over a 100M-row sort through the door takes 64 FETCHes, one per client slot, where the
first fix alone would spin for as long as the sort ran. The bench is unchanged apart from the hold's
cost on an early stop: `LIMIT 1` over 1B rows 0.144 s and +56 MiB, the full read 3.79 s and
+57 MiB, the slow read 10.44 s and +408 MiB.

**Addendum 2026-09-23: many clients at once** (`test/bench/door_concurrent.py`). N separate quack
clients start together against one server. Their kinds are assigned in turn: full reads of 50M rows,
`LIMIT 1`, slow single-thread readers and `LIMIT 10` over a sort. Every client checks its own answer.
Three runs per cell, one 16-core machine:

| clients | window | LIMIT 1 | full read | wall | server peak |
| --- | --- | --- | --- | --- | --- |
| 8 | 8 | 0.17-0.25 s | 0.73-0.84 s | 1.30-1.35 s | +2.5-2.8 GiB |
| 8 | 0 | 0.84-0.95 s | 0.81-0.89 s | 1.37-1.55 s | +3.4 GiB |
| 16 | 8 | 0.25-0.43 s | 1.02-1.36 s | 1.75-1.95 s | +4.4-4.8 GiB |
| 16 | 0 | 1.46-1.87 s | 1.52-1.82 s | 2.12-2.27 s | +5.8-6.2 GiB |

- **Within capacity.** Every answer was right in every run. Under contention the window wins nearly
  everywhere, because the server stops producing batches for clients that stopped.
- **Past capacity.** The door's worker pool, quack's own ElasticThreadPool copied as is, keeps one
  thread per keep-alive connection up to `acl_quack_server_max_connections` (1024). At the cap it
  sheds a new connection, and the client's query fails with "Server returned nothing". A quack
  client keeps one connection per FETCH in flight, 64 by default, so the door seats about 16
  clients at once. With 24 clients, some queries failed in both modes: 1-2 per run with the window,
  3 without. With the clients' `quack_fetch_read_ahead = 8`, 32 clients all passed. The window
  cannot change this: the connections are the client's.
- **The fix it found.** With the window, some over-capacity clients hung for 30 s before failing.
  An empty answer was held for production below a batch whose FETCH had been shed. The hold for
  production now needs that FETCH to have arrived (above). With the fix, no 30 s stalls occur in
  three runs of 24 clients, or on a pool of 64.
- **Memory has no global bound.** The server's peak grows with the clients, because each stream may
  buffer `acl_quack_fetch_producer_buffer_bytes` (256 MiB, at most a quarter of the memory limit)
  and its producer's threads hold their fragments. The window lowers it by about a quarter. A
  budget across streams belongs with the resource groups follow-up.
- **A tooling note.** With `-csv` or `-list` output, the duckdb CLI printed nothing for an error
  raised while a result streamed, such as a FETCH that fails. The client looked like it answered
  nothing. Box mode prints the error, and the bench uses box mode.

## Alternatives considered

- **Hold a FETCH beyond the window until the client acknowledges more.** This hangs every early
  stop, because the client waits for its outstanding FETCHes before it cancels.
- **Answer beyond the window with the end of the stream.** This truncates the result silently, or
  fails it on the client's count.
- **The batch size alone (spec 063).** It still multiplies by the client's depth, and it costs every
  full read.
- **A server-announced maximum read-ahead.** This is the protocol fix, and it is suggested on #277
  as a version-gated field next to the handshake's heartbeat. It needs quack, not us.
- **A patch to the quack client.** Clients are not ours: stock quack from any machine connects to the
  door.

## Follow-ups

- **The door's capacity.** About 16 quack clients at once with the default read-ahead. The options
  are a larger `acl_quack_server_max_connections`, where a thread per connection is the price; a
  pool that does not pin a thread per idle keep-alive connection, which is quack's and httplib's
  design; or a server-announced read-ahead, as suggested on duckdb-quack #277. The last one also
  caps the connections a client opens.
- **Resource groups.** The window and its cap are GLOBAL today. Binding them, and the batch size, to
  a profile per role or per token is future work: the cap is the per-client number of batches a
  class of service may hold. The seam is `AclQuackFetchWindowFor`, which reads both when a stream's
  first FETCH arrives.
- **When #277 lands in the pinned quack.** Re-measure with the window at 0. If the client stops early
  by itself, the window can default to 0, and spec 063's batch can go back to quack's 32 MiB.
