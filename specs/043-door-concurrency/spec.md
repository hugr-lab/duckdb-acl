# Spec 043: several clients, real sources, at the same time

- **Status**: draft
- **Date**: 2026-08-22
- **Author**: hugr-lab

## Summary

Everything proven about the door so far was proven by one client, against tables in memory, inside the
test runner's own process. This adds the missing half: a server process holding **real attached
sources** (postgres, mysql, and SQL Server where it is available), and **several client processes**
under different roles reading and writing
through it at the same time. What it has to establish is not that nothing crashes but that isolation
holds under overlap — each principal sees its own slice and only its own, no write lands outside the
slice that caused it, and no principal ever reaches a statement that belongs to another connection.

## Problem

Two halves of this system are each well tested and have never met.

- `acl_postgres` / `acl_mysql` / `acl_cross_source` prove the policy works over live sources — but one
  client asks, inside the runner's process, one statement at a time.
- `acl_quack_serve` / `acl_quack_ingest*` prove the door works — but the physical tables are in memory
  and there is exactly one client.

So the interesting deployment — a served instance, real sources behind it, several clients at once —
is the one nothing covers. Three properties are only reachable there:

- **A principal must not leak between connections.** `parser_override` receives no `ClientContext`
  (spec 040), which is *why* identity rides in the statement text; the door binds it per message
  through quack's `connection_id`. That design is sound on paper and has never been run against two
  clients whose statements interleave on a pooled connection. A leak would be the worst bug this
  project can have, and it is invisible with one client.
- **A drained stream into a real source is a different write path.** Spec 042's ingest lands in a
  duckdb table. Through `postgres_scanner`, `mysql_scanner` or the SQL Server extension the insert goes
  somewhere else entirely — a different one for each — and quack asks the planner for a *parallel*
  insert on an unordered stream. Whether that works, serializes, or refuses is unknown per source, and
  bulk loading into a real source is the point of the door.
- **An ingest is atomic per statement, not per stream** (spec 042). With one client that is a sentence
  in a document. With a second client reading the same table while the first drains, it is something a
  test can show — and something an operator needs told.

## Design

### Shape: processes, not connections

sqllogictest can express this only weakly. It has named connections (`statement ok con1`) and
`concurrentloop`, but both give several connections **inside one process**, and the door is a socket:
what matters is quack's own connection handling, its pooling, and the per-message binding. Two client
processes model that; two connections in the runner model something adjacent to it.

So this lands as a script, in the shape `test/harness/run.sh` already has:

```
test/e2e/door/
  bootstrap.sql      # what the server runs: attach the source, own its table, define policy, serve
  client.sql         # one client's work, parameterised by token/tenant/row count
  run.sh             # one leg per source: start, wait, run both clients, check, stop
```

`make test-e2e` runs it. `bootstrap.sql` is source-agnostic — the ATTACH and the physical name are
substituted per leg — so adding a source is a few lines in `run.sh` and nothing else.

**That the load is genuinely streamed is structural, not hoped for.** Each client builds its payload in
a table of its own, which the server cannot see; quack therefore has no way to push the statement and
must send the data. So every passing row count is evidence that spec 042's drain path ran.

### Topology

One server process (`build/release/duckdb` with the extension loaded) attaches postgres, mysql and SQL
Server, publishes a virtual catalog over all three, defines roles and grants, and calls
`acl_quack_serve`. Several client processes attach `quack:…` with different tokens — different roles,
different `tenant` claims — and run overlapping work.

**Each source is a leg that can be absent, and the run says which legs it ran.** This matters more than
usual here:

- **SQL Server never runs in CI.** The workflow starts postgres and mysql services only, and the
  existing `acl_sqlserver` scenarios already skip there. So the mssql leg is local coverage, and the
  run has to report that it was skipped rather than quietly pass as if three sources had been covered.
  It also needs its own build flag (`ACL_INTEGRATION_MSSQL=1`), which is easy to forget.
- **SQL Server on macOS runs under emulation**, slow enough to matter for a test built out of timeouts.
- **mysql has no leg at all right now**: `mysql_scanner` is disabled at the current submodule pin
  ("patches do not apply"), so the source cannot be attached by anyone, in CI or locally. Recorded here
  because a leg that cannot be built is not the same as one that is merely absent today.

A skipped leg is a reported skip, never a silent one, and **the skip carries the reason the probe
gave**. That is not politeness: building against the current duckdb pin leaves an mssql extension in
the repository directory that was built for the *previous* pin and refuses to load, and a skip that
only said "not reachable" hid exactly that for a while. A stale artifact and a database that is not up
must not look the same. The run also fails outright if **no** leg ran, so "everything skipped" can
never read as a pass.

One instance serves one policy: both callback settings are `SetScope::GLOBAL`, so "different roles"
means different sessions on one server, not different servers. That is the deployment, not a
simplification.

### What is asserted

Assertions about **content**, not about exit codes:

- **Slices stay separate.** Each client reads its own rows throughout, while others write. Not "reads
  something" — the exact set.

  **Judged by `id`, not by `tenant`, and that correction is worth keeping.** The first version checked
  for rows of another tenant, which looked like the strongest possible assertion and was in fact
  vacuous: the grant *computes* `tenant` from the principal's claim, so every row reads back carrying
  the reader's own tenant whatever is stored underneath. The check could not fail. Found by breaking
  the policy on purpose — removing the RLS — and watching the run fail on a row *count* while the
  headline assertion stayed silent. `id` is neither masked nor injected, and each client writes into a
  range of its own, so a row from anywhere else is visible as itself.
- **A write never lands outside the slice that caused it.** After the run, no row anywhere carries a
  tenant other than the one whose client wrote it. The predicate is checked where the value is written
  (spec 024), so a breach shows up as a stored row, not as an error nobody read.
- **Concurrent bulk ingests into one table add up.** Two clients drain into the same physical table at
  once; the totals per tenant are exactly what each sent, and neither lost rows to the other.
- **A concurrent reader sees only its own rows** while an ingest runs. It may see *some* of another
  batch's effect on totals — the ingest is one statement per stream, so a reader mid-drain sees either
  its whole effect or none — but it must never see a row belonging to a tenant that is not its own.
- **Cross-source under load.** One client joins postgres to mysql through its catalog while another
  writes into postgres. The join's result is the joining role's slice, unaffected by the writer. Where
  the mssql leg runs, a three-source join is the same assertion with one more source in it.
- **A drained stream reaches each source.** Bulk ingest is exercised per source rather than once,
  because the write path is the scanner's and differs between them — this is the assertion most likely
  to come back with an answer we did not expect.
- **Session lifecycle does not cross clients.** Closing one client's session, or its process dying
  mid-statement, leaves the others working. `acl_quack_stop` sweeps sessions when the door closes; that
  is the end of the run, not a thing one client can do to another (the functions are denied to a
  principal — spec 040).

### Mechanics that decide whether this is a good test or a flaky one

- **Readiness is polled, never slept for.** The server is ready when a client can connect, so the
  clients wait on that condition with a timeout, not on a fixed delay.
- **Every process is cleaned up on any exit.** A `trap` kills the server and the clients; a listener
  surviving a failed run poisons the next one — and spec 041 measured that a stopped quack listener can
  keep answering for a while, so the port is not proof the process is gone.
- **A hang must fail, not block.** Each client runs under a timeout; CI must not sit on a deadlock.
- **The run owns its data.** Tables are created and truncated by the bootstrap, with names of this
  test's own, so a rerun is clean and a leftover row cannot pass for a bug (or hide one).
- **Overlap is made likely, then repeated.** Concurrency tests that interleave once by luck prove
  little; enough rows that the drains genuinely overlap, and the whole run repeated a few times.

### What has landed, and what has not

The harness exists and runs three legs — postgres, mssql, ducklake — each with two clients under
different tenants streaming 20 000 rows apiece into one table at the same time. Whole run: about eight
seconds. What it asserts today is the first three items above: slices stay separate, no row is stored
outside the slice that wrote it, and concurrent ingests add up.

Not yet written, and the reason each is a step rather than a line:

- **a reader running *during* another client's drain** needs a third client whose statements interleave
  with a load in flight, which is a different orchestration than "start two, wait for both";
- **the cross-source join under load** needs a second published object over another source, and with
  mysql unavailable the interesting pairing is postgres × ducklake or postgres × mssql;
- **session lifecycle across clients** — one client's session closed or its process killed mid-statement
  while the others keep working.

### Verified by breaking it

A test that has only ever passed proves nothing about what it would catch. Removing the grant's RLS
and re-running is part of writing this: the run must fail, and it must fail *on the isolation
assertion*. It did not the first time — which is how the vacuous check above was found — and does now.

### Measuring, and what it found

Two instruments, because "what does the ACL cost" is two questions:

- **`test/bench/rewrite_cost.py`** — per statement, no socket. The same physical query reached natively,
  through a grant that is a plain rename, and through a grant with a projection and a claim-baked
  predicate. It also carries a column for the extension *not loaded at all*, which measures the toll we
  charge statements that are not ours.
- **`test/bench/door_throughput.py`** — parallel client processes against a served instance, in five
  configurations: plain quack; quack with an identity authorization callback; and the ACL under grants
  of increasing complexity, plus a schema alias. Reads are timed inside the client (so process startup
  stays out); the connect is timed on its own, cold and warm; writes are end-to-end.

What they say, measured rather than assumed:

- **Statements that are not ours are free.** Loading the extension costs an unprefixed statement
  nothing measurable (−3µs to +19µs, i.e. noise), so the prefix scan and the spec-042 fence are not a
  tax on a co-tenant workload.
- **Our machinery is ~25–70µs per statement and does not grow with the number of object references** —
  four references to an object in one statement cost no more than one, so the template cache is doing
  its job.
- **Through the door, per-statement cost disappears into the noise**: 96–103% of plain quack's
  per-statement time for reads, whatever the grant says.
- **The cost is concentrated in the connect: about 4x** (≈50ms plain, ≈220ms under the ACL, warm; the
  first connect after a server starts adds ~100ms more). It parallelises well — eight clients connect
  in barely more time than one — so it is latency, not a serialised bottleneck.
- **The shape of the policy barely matters.** A plain rename, a column list, a predicate, an assigned
  column and all of them together land within a few percent of each other. **A schema alias does not
  help either** — the same 4x connect — so the cost is not in resolving names or in the number of
  published objects.

So: nothing to optimise per statement, and one clear question left — what those ~170ms of connect are
spent on. Deliberately not chased here; the point of this round was the instrument.

An honest note on the write figure: a streamed insert is sent by the client and drained by a statement
on the *server*, so the client's own timer stops when the data is away rather than when it is written.
Writes are therefore reported end-to-end with the connect included, which at any sane volume is
dominated by that 4x connect. Subtracting the connect was tried and abandoned - the phase is shorter
than a connect, so the subtraction produced noise and occasionally negatives.

## Enforcement & security

This spec adds no enforcement — it is a proof about the enforcement that exists. What it can establish
is negative and specific: after N clients under M roles have overlapped, **no row exists outside the
slice of the principal that wrote it, and no client ever read a row outside its own**. A failure here
is not a test bug to be relaxed; it is the model being wrong.

The one new risk the *test* introduces is a server left listening after a failed run, which is an
operational nuisance rather than an exposure — it serves the same policy it was started with.

## Testing

The deliverable is the harness itself. Beyond it, two smaller things worth pinning in the ordinary
suite while this is written:

- an in-process interleaving of two roles through named connections, for the parts that do not need a
  socket — cheap, deterministic, and it fails fast when the rewriter grows per-instance state it should
  not have;
- the parallel-insert plan for an unordered stream, which spec 042 left unpinned.

## Alternatives considered

- **`concurrentloop` in sqllogictest.** One process, and a failing statement inside it is recorded
  rather than thrown — good for finding crashes, poor for asserting content.
- **A C++ test with threads.** Closer to the real thing than one process of SQL, still not the door:
  it would exercise our store under threads while skipping quack's connection handling, which is the
  part with no coverage.
- **Leave it to the gateway's own tests.** The gateway is a separate repo and a different component;
  the door has to stand on its own, because a client connecting directly is exactly the case the
  gateway is not in.

## Follow-ups

- **What a stopped door does to a client mid-stream** deserves its own answer once this exists; spec
  041 already records that the socket outlives the stop.
- **Session sweeping and a cap on live sessions** (spec 040's open follow-up) becomes testable here:
  many clients opening and abandoning sessions is exactly the load that shows an unbounded map.
