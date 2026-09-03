# Spec 069: Audit - a record of every decision the engine makes

- **Status**: draft (a proposal for the owner's review; nothing implemented)
- **Date**: 2026-09-04
- **Author**: hugr-lab

## Summary

Every decision the ACL makes about a principal - a statement admitted or refused, a session opened or
refused, a management statement authorized or refused, an ingest accepted - is recorded as one event:
who, what kind of statement, which virtual objects with which capability, the verdict and its reason,
and a correlation id the caller supplied. **Never data**: no statement text, no parameter values, no
rows, no claim values. Events are kept in a bounded in-process buffer an operator reads through a
table function, and shipped out through a sink the operator configures. The cluster repo depends on
this existing; it cannot reconstruct it, because only the node knows what it decided.

## Problem

Today the only trace of a decision is the error the client got, or did not get. Nobody can answer
"who read `orders` yesterday", "which statements did role `analyst` have refused this week", "did
principal P ever reach `sales.ssn_backup`", or "the front saw request R fail - what did the node
decide". A gateway can log what it *sent*; it cannot log what the node *decided* - the objects a
rewrite resolved, the capability it judged, the reason of a refusal - and a security review cannot
reconstruct any of it after the fact. Decided 2026-09-03: this is in the first release.

## Design

### The event

One record per decision:

| field | type | what |
| --- | --- | --- |
| `ts` | TIMESTAMPTZ | when the decision was made |
| `seq` | BIGINT | monotonic per instance; a gap is a dropped event (see *Sinks*) |
| `node` | VARCHAR | `acl_node_id` when set, else `<hostname>:<pid>` |
| `door` | VARCHAR | `flight`, `quack`, `gateway` (a prefix on a plain connection), or `admin` (a bare `ACL ADMIN`) |
| `session` | VARCHAR | the ops id `acl_sessions()` shows - never the handle - or NULL |
| `subject`, `issuer`, `roles` | VARCHAR, VARCHAR, VARCHAR[] | the principal; the `ROLE` form has roles only |
| `kind` | VARCHAR | `statement`, `admin`, `session`, `ingest`, `door` |
| `statement` | VARCHAR | the class: `SELECT`, `INSERT`, `CREATE TABLE`, `MANAGEMENT`, `NATIVE`, … - never the text |
| `objects` | STRUCT(name VARCHAR, capability VARCHAR)[] | every virtual object the resolution touched, with the capability judged for it |
| `verdict` | VARCHAR | `allowed` or `denied` |
| `reason` | VARCHAR | on `denied`: our refusal, prefix included (`acl_rewrite: insert into read-only relation "orders" is not allowed`); NULL on `allowed` |
| `correlation_id` | VARCHAR | what the caller supplied (below), else NULL |
| `rewrite_us` | INTEGER | the decision's own cost |

What is deliberately **not** there: the statement text, parameter values, anything read or written,
claim *values* (a tenant id is a fact about a person; roles and subject identify the principal well
enough), physical names (the reason is our refusal text, which names virtual facts only - spec 065).
An error duckdb raises later, at bind or execution, is not our decision and is not recorded by us:
the event for that statement says `allowed` with its objects.

### Where decisions are made - the seams that emit

- **The rewriter** (`RewriteStatements`): one event per statement of the batch. The walker already
  holds the `TablePolicy` of every reference it resolves and the capability it checked; it records
  them into an `AuditTrail` carried through the walk (the way `Principal` is), and the override emits
  the event when the rewrite returns or throws - `allowed` with the objects, or `denied` with the
  refusal. One event covers a whole batch under one prefix only when the batch is refused before any
  statement is walked (a prefix that does not parse, a principal that does not verify).
- **`AuthorizeMgmt`**: kind `admin`, `statement` = `MANAGEMENT`, objects = the catalogs a statement
  targets, verdict per batch (a management batch is authorized as one - spec 009).
- **`SessionOpen`** and the doors: kind `session` - opened, or refused with the reason the door never
  shows the client (`token rejected: …`, `draining`, `at acl_max_sessions`). Kind `door` for the
  password handshake and its refusals (spec 064).
- **Ingest** (specs 042/049): kind `ingest`, the target object with `insert`, the verdict. Not the
  row count: a count is not data, but it is execution's answer, not the decision's, and v1 records
  decisions only (see *Follow-ups*).

### The correlation id

The caller supplies it; the node never invents one (a request id that no other system has is worth
nothing). Three ways in, one field out:

- a **prefix marker** for a gateway, which shares a connection between principals and cannot afford a
  `SET` per statement: `ACL TOKEN '…' TRACE '<id>' <sql>` (and the same after `ROLE`/`SESSION`), the
  id up to 128 printable bytes, single quotes doubled;
- a **client-local setting** for a served session (spec 068's allowlist grows by one):
  `SET acl_correlation_id = '<id>'`, stamped on every statement of that session until changed;
- the **Flight door** also reads the gRPC metadata key `x-correlation-id` on each call, which is what
  ADBC/JDBC clients can set without touching SQL.

### Sinks

- **The buffer**, always on: a ring of `acl_audit_buffer` events (default 10 000, `0` = off), read by
  `acl_audit_events()` - a table function of the operator's, denied to a principal like the rest of
  the ops surface. The newest events; `acl_audit_dropped()` says how many the ring or the sink lost.
- **A file**, `SET GLOBAL acl_audit_sink = '<path or URI>'`: one JSON line per event, appended
  through duckdb's own filesystem (a local file works out of the box; an object store rides httpfs,
  the spec-023 pattern), by a writer thread fed from a bounded queue (`acl_audit_queue`, default
  10 000). The thread flushes every 100 ms or 1000 events. **A full queue drops the event and counts
  it; a failing sink counts and keeps trying; neither ever delays or fails a statement** - the audit
  must not be the way to take the node down, and must not be an availability dependency of the data
  path.
- Rotation is the operator's (`logrotate` with copytruncate, or a path with a date the operator
  changes); the writer reopens the file when the setting changes.

### What it costs

Composing an event is a handful of small strings; the ring push is one mutex; the file write is on
another thread. Against the 25–70 µs the rewrite itself costs (spec 043's measurement) this is
noise; `test/bench/rewrite_cost.py` gets a column for "with audit" to keep it honest.

### What it is not

Not a query log (no text). Not row-level access logging (no rows). Not tamper-evident (the file is
the operator's; signing, forwarding and retention are the fleet's business). Not consulted by
enforcement - nothing decides differently because of what was recorded.

## Enforcement & security

- **Never data** is structural: the event is built from the decision's own facts - `TablePolicy`
  names, the capability, the verdict, our refusal text - and the code path never sees the statement
  text as a value to record. A reviewer can check the one constructor.
- The audit surface is the operator's. `acl_audit_events()`, `acl_audit_dropped()` and the settings
  are unreachable under a principal (the function gate and the settings gate of spec 068).
- Fail-open by design: a dropped event is counted, never a refused statement. Stated here so nobody
  reads "audited" as "guaranteed"; a strict mode is a follow-up.
- The correlation id is the caller's string, untrusted: bounded in length, JSON-escaped on the way
  out (`JsonQuote`), never interpreted.

## Testing

- sqllogictest: after a handful of prefixed statements, `acl_audit_events()` shows exactly them - an
  allowed `SELECT` with `[{orders, select}]`, a refused `INSERT` with its reason, a session refused
  for a bad token, a management batch authorized and one refused, a `TRACE` id and a set
  `acl_correlation_id` both arriving in `correlation_id`; a principal calling `acl_audit_events()` is
  refused; a buffer of 5 after 10 events holds the last 5 and reports 5 dropped.
- The file sink: set to a temp path, run statements, `read_json_auto` reads them back with the same
  fields; an unwritable path counts drops and the statements still run.
- C++ (`make test-cpp`): the writer thread with a stalled sink never blocks a decision (bounded by
  time); N threads' events are all present or counted, never lost silently
  (`test_acl_concurrency.cpp` grows an audit tally).
- The door harness: one `session` event per client connection.

## Alternatives considered

- **A table in the policy catalog.** Durable and queryable through management SQL - and every
  statement becomes a write into the database the resolver reads from (postgres, SQL Server), shared
  by every node: latency on the hot path and contention for the one thing that must stay fast. A
  fleet that wants it durable tails the JSON lines into whatever it runs.
- **duckdb's own logger** (`duckdb_logs`). A log of strings, not a record with our fields; and a
  principal can read `duckdb_logs` unless denied (it is in our denylist for that reason). It may
  become one more sink transport later, not the model.
- **Auditing at the gateway.** It knows what it sent, not what the node decided - the objects, the
  capability, the reason. That is the half nobody else has.
- **Emitting on execution rather than on decision.** Would add row counts and duckdb's own errors;
  needs an execution hook the parser override does not have. The decision is what the ACL owns.

## Follow-ups

- A callback sink for the cluster (a registered function, the function-driver's shape) beside the
  file.
- `acl_audit_strict`: refuse the statement when its event cannot be recorded, for deployments that
  prefer unavailability to an unrecorded decision.
- Row counts of executed statements, once an execution hook exists.
- Reports derived from the events (`who read what`), as SQL over `read_json` - documentation, not
  code.
