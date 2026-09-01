# Spec 066: Node drain — stop taking new clients, then let the operator stop the node

- **Status**: implemented
- **Date**: 2026-09-01
- **Author**: hugr-lab

## Summary

An operator can put a serving node into **drain**: the node stops accepting new clients while every
established session keeps working, so in-flight statements, transactions, ingests and fetch streams
finish naturally. The operator watches the live-session count fall, kills stragglers if the deadline
arrives first, and then stops the node from outside — `acl_flight_stop` / `acl_quack_stop` and then
closing duckdb (or terminating the process). Three functions carry it: `acl_drain()`,
`acl_resume()`, `acl_drain_status()`. The node does **not** wait or time out by itself: the waiting
and the deadline belong to the orchestrator that is stopping it (systemd, k8s, a script) — the node's
job is to refuse new work honestly and to stay observable while the old work ends.

## Problem

Today the only way to take a node out of service is `acl_quack_stop(uri)` / `acl_flight_stop(uri)`,
which stop accepting **and tear down at once**: the listener closes and the sessions the door served
are swept. A client mid-fetch loses its stream; a session mid-transaction loses it; a rolling
restart behind a load balancer has no window in which old clients finish while new ones land on
another node. What is missing is the intermediate state every serving system has — draining — and a
way to observe it from outside.

## Design

### Drain is one flag at the one seam every new client crosses

Every path that turns a stranger into a session goes through `PolicyStore::SessionOpen`:

- quack's per-connection authentication callback (`acl_quack_authenticate`, spec 041),
- the Flight door's `SessionFor` — both the durable cookie session and the cookie-less per-call
  session (spec 050),
- the gateway-side session contract (`acl_session_open`, spec 040).

Established sessions never touch it again: statements resolve through `SessionPrincipal` /
`SessionSql`. So drain is a single `std::atomic<bool> draining` on the `PolicyStore` (per instance,
like the sessions themselves), and `SessionOpen` refuses — before verifying anything, since there is
nothing to learn from a token the node will not seat — while it is set. That one refusal covers both
doors and the gateway contract with no per-door state machine, and it fails closed: a door that
forgot to check still cannot seat a client.

The doors additionally check the flag at their own establishment points, only to say *why*:

- **Flight**: `SessionFor`'s fall-through to `SessionOpen` (a new client, or a re-authentication as
  a different principal) answers `Unavailable: acl: node is draining - not accepting new sessions`
  instead of the generic authentication failure. A resolving cookie session is untouched. The
  password handshake (spec 064) is also refused while draining — it exists only to seat new clients,
  and running the IdP grant for a client the node will refuse is wasted and noisy.
- **quack**: the authentication callback answers NULL, which quack turns into its own refusal (the
  callback's contract carries no message). The discovery document signals instead:
  `GET /.well-known/quack-auth` answers **503** with body `draining` while the flag is set — the
  standard health-check shape a load balancer or an ops probe already watches.

Nothing else changes behaviour under drain, deliberately:

- An established session may still run statements, begin transactions, start a new ingest, redeem
  reservations, drain quack streams. Drain bounds *who*, not *what*: the deadline for how long the
  old clients get is the operator's, and cutting a session off mid-work is exactly what drain exists
  to avoid. A straggler past the deadline is ended by `acl_session_kill(id)`, which already exists.
- `ACL TOKEN` / `ACL ROLE` prefixed statements (the gateway deployment, spec 001) are stateless and
  keep working: in that deployment the gateway is the thing doing the draining, and the node
  refusing its statements mid-flight would turn a graceful stop into an outage.
- Policy administration, `acl_sessions()`, `acl_session_kill`, the serve/stop functions — all
  unchanged: draining is when the operator most needs the ops surface.

### The operator surface

```sql
SELECT acl_drain();        -- enter drain; sweeps, then returns the live-session count (BIGINT)
SELECT acl_drain_status(); -- 'serving' | 'draining'
SELECT acl_sessions();     -- who is still here (ops ids, spec 050)
SELECT acl_session_kill('<id>'); -- the deadline arrived first
SELECT acl_resume();       -- leave drain; true if it was draining, false if it already served
```

`acl_drain()` is idempotent, and it **sweeps before counting**: spec 044 put the automatic sweep
inside `SessionOpen` ("the operation that grows the map pays to clean it"), and drain turns that
operation off — on a draining node nothing would ever collect the idle and the expired, and the
watched count would sit above what is really there. So the drain surface pays instead, and
*repeating `acl_drain()` is the watch loop*: each call re-answers what genuinely remains. All three are
registered in the same class as the session functions: **denied to a principal** through the prefix
(spec 040's rule — a client can neither drain the node nor read its drain state), available on the
node's own connection and to a passthrough admin (`ACL NATIVE`, spec 009).

### The supported stop sequence

```text
acl_drain()                         -- new clients now land elsewhere
repeat acl_drain() → 0              -- the watch loop (sweeps + counts), or the orchestrator's deadline
acl_session_kill(...)               -- stragglers, if the deadline came first
acl_flight_stop(uri) / acl_quack_stop(uri)   -- synchronous teardown (spec 063)
close duckdb / terminate the process
```

Stopping the doors before closing duckdb matters for the Flight door: its process-wide registry
holds a `DatabaseInstance &`, so an instance closed under a still-listening Flight door is a
dangling reference (the quack door detects a dead instance and refuses, spec 063). Terminating the
whole process is always safe. Making the Flight door survive instance death the way quack does is a
follow-up, not part of drain.

### Data structures

`PolicyStore` gains `std::atomic<bool> draining{false}` and three methods: `SetDraining(bool)`
(returns the previous value), `Draining()`, plus the existing `SessionCount()` for the return value
of `acl_drain()`. No schema change, no settings: drain is runtime state, not configuration — a
restarted node serves (a node that must come up draining can call `acl_drain()` in its init script
before serving).

## Enforcement & security

- **Fail-closed at the seam**: the refusal lives in `SessionOpen` itself, not only in the doors, so
  any future establishment path inherits it.
- **Refuse before verify**: a draining node does not verify the token first — there is nothing to
  decide with the result, and the early refusal keeps the drain path free of JWKS reads.
- **No new authority**: drain functions are denied to principals like the rest of the session
  surface; a client cannot drain a node, resume one, or observe its drain state. The 503 on quack's
  discovery reveals only what refused connections would reveal anyway.
- **No eviction**: drain never ends a session (spec 044's rule stands — ending somebody's session is
  the worse failure). Ending one is `acl_session_kill`, an explicit operator act.
- **Golden rule untouched**: no rewriting changes; drain adds no parameters and touches no AST.

## Testing

- **sqllogictest** (`test/sql/acl_drain.test`): status starts `serving`; `acl_drain()` returns the
  live count and flips status; `acl_session_open` answers NULL while draining; a session opened
  *before* the drain still composes through `acl_session_sql` (in-flight clients continue);
  `acl_drain()` idempotent; `acl_resume()` true→false; after resume `acl_session_open` mints again;
  all three functions refused through an `ACL` prefix (denied to a principal).
- **C++ (quack embed)**: in `test/cpp/test_acl_quack_embed.cpp` — serve, connect and query; drain;
  the established connection still answers; a fresh connection is refused at authentication;
  `/.well-known/quack-auth` answers 503/`draining`; resume; a fresh connection succeeds again.
- **Flight e2e** (`test/e2e/flight/drain.sh`): an ADBC client connects (durable cookie session) and
  keeps querying across the drain; a second client connecting during drain is refused with the
  draining message; after `acl_resume()` it connects.

## Alternatives considered

- **A node-side drain timeout** (`acl_drain(seconds)` that kills what remains): rejected — the
  deadline belongs to the orchestrator that is stopping the node, which already has one
  (terminationGracePeriod, TimeoutStopSec); a second, competing timer inside the node adds a race,
  not safety. `acl_session_kill` covers the stragglers explicitly.
- **Refusing statements from established sessions too**: rejected — that is a stop, not a drain; the
  whole point is letting in-flight work finish.
- **Per-door drain** (`acl_flight_drain(uri)`): rejected — the node serves one policy per instance
  (both quack callbacks are GLOBAL settings), sessions are per instance, and the operator's unit of
  rotation is the node; per-door state buys nothing but a matrix.
- **A management-SQL form** (`ACL ADMIN DRAIN NODE`): skipped for now — drain is an operator's act on
  the node's own connection (or passthrough), not part of the policy language; grammar can follow if
  a deployment wants it.

## Follow-ups

- The Flight door's registry holding `DatabaseInstance &`: make an instance closed under a listening
  door refuse like quack's does, instead of relying on stop-before-close.
- Live in-flight *statement* observability (active reservations / running requests per door) if
  watching the session count proves too coarse in practice.
- The shared session backend a cluster needs (spec 040 follow-up) would make drain state per-node
  while sessions roam; drain stays per-node by design.
