# Spec 080: the node's stream budget

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: hugr-lab
- **Design**: 076 (local), phase P1, second half. The first half is spec 079 (seats and the load
  report).

## Summary

A quack statement's stream buffers what it produces until the client fetches it: the producer
buffer, the batches in flight, and the producer threads' fragments. This memory is not governed by
duckdb's buffer manager, and nothing bounded its sum across the node. In the concurrency bench, 8
clients took +2.5 GiB and 16 took +4.4 to 6.2 GiB, with no ceiling.

The node now has a stream budget:

- **Reserve.** A producing quack statement reserves its worst case for as long as it produces.
- **Wait.** A statement that finds the budget full waits on its node, in arrival order. This is how
  a sticky session's next statement waits for capacity (the owner's design point).
- **Refuse.** When the wait runs out, the statement fails with the reason, and the client's PREPARE
  answers it.

## Design

**`StreamBudget`** is header-only (`acl_stream_budget.hpp`) and belongs to the store.

- **Acquire.** `Acquire(bytes, budget, timeout, interrupted)` hands out tickets and serves them in
  arrival order. A ticket is admitted when it is at the head and `reserved + bytes <= budget`.
- **A stream larger than the budget.** A lone stream whose reservation alone exceeds the budget is
  admitted once nothing else is reserved, because it must run eventually.
- **Giving up.** A ticket that gives up in the middle of the queue is remembered and skipped when its
  turn comes, so nothing behind it waits for it.
- **Interruption.** A client that went away, seen as the connection being interrupted, stops the
  wait. That is not counted as a refusal.
- **Counters.** It counts reserved bytes, producing statements, queued statements, and refusals.

**Where the reservation is taken.** It is taken in the server's statement driver, through a `sync.py`
patch: an `AclQuackStreamSlot` inside the `try` around `Query()`.

- **Waiting.** It waits there. The client's PREPARE waits with it, because PREPARE waits for the
  stream to bind.
- **Refusing.** It throws the refusal, and the driver turns it into the stream's error, which PREPARE
  answers.
- **Releasing.** It releases when `Query()` returns, that is, when production ends. After that, the
  stream holds at most its producer buffer until it is drained. That remainder is bounded, but not
  reserved.

**What a stream reserves.** `acl_quack_stream_reserve_bytes`, or when that is 0:

- the producer buffer, capped as the server caps it at a quarter of the operator memory limit;
- plus the window's cap times the batch;
- where the window's cap is `acl_quack_fetch_window_max`, or the client depth when the window grows
  without a cap.

The default is 256 MiB + 64 × 8 MiB = 768 MiB. That is pessimistic against the measured 150-350 MiB
a stream holds, so it can be set.

**Settings**, all GLOBAL:

- `acl_node_stream_budget`: 0 means half of the operator memory limit.
- `acl_quack_stream_reserve_bytes`.
- `acl_stream_queue_timeout`: 25 s, and 0 means refuse at once.

The timeout differs from the 30 s the owner decided. The quack client's own HTTP timeout is duckdb's
`http_timeout`, 30 s, and the refusal has to reach the client before the client gives up on its own.

**The refusal's text:** `acl: node at capacity - the stream memory budget stayed full for 25 s (768.0
MiB of 8.0 GiB reserved by 10 producing statements, 768.0 MiB wanted); try again or another node`.

**Reporting.**

- `acl_node_load()` gains `streams`: `budget_bytes`, `reserve_bytes`, `reserved_bytes`, `producing`,
  `queued` and `refused`. It also gains `admit.new_stream`, which is true when nobody waits and a
  reservation would fit now.
- The gauges are `acl.streams.reserved_bytes`, `.producing`, `.queued` and `.refused`.

**Flight.** The Flight door holds one chunk per stream (spec 070), and it is not reserved.

## Enforcement & security

- **Not an enforcement feature.** The budget only delays or refuses a statement the decision already
  allowed. The refusal is the node's, and it says so.
- **Every statement waits.** A statement that is not a result stream, such as a count or a drain,
  reserves too. When the node is saturated, every statement waits its turn.

## Testing

**`test/cpp/test_acl_stream_budget.cpp`**, first the budget under threads:

- a lone oversized stream runs, and budget 0 admits everything;
- a statement waits and runs when the room frees;
- a wait that runs out is refused and counted;
- an interrupted wait is not counted;
- arrival order holds: a small statement that would fit does not overtake a big one that arrived
  first;
- a ticket that gives up in the middle does not block the one behind it.

Then the door, with room for exactly one stream and a 1 s wait:

- a heavy view holds the room, and a second client's statement is refused with the reason;
- it runs once the room is free;
- `acl_node_load()` counts the refusal.

**The bench**, `door_concurrent.py` with 6 clients and a one-stream budget:

- with the default wait, all 6 complete one after another at a server peak of +647 MiB;
- with wait 0, 5 are refused with the reason and 1 runs.

## Alternatives considered

- **Measuring what each stream holds right now and admitting against that.** Rejected: the sum moves
  under the admission, and the worst case is what running out of memory is about.
- **Releasing when the stream object dies.** Rejected: a connection's next statement would wait on
  its own previous stream's reservation, and a retained result cache would hold it for its TTL.
- **Queueing in the orchestrator.** Rejected: only the node knows when a reservation is released.
  The orchestrator reads `admit.new_stream` to avoid a node for new work.

## Follow-ups

- The reservation is a worst case. With the server-announced read-ahead (P2, duckdb-quack #277), the
  window cap becomes the client's real depth, and the default drops.
- Resource groups (P3) would give a profile its own reserve, and a priority in the queue.
