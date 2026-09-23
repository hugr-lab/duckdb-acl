# Spec 079: the node's seats and its load report

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: hugr-lab
- **Design**: 076 (local), phase P1, first half. The stream-memory budget and its queue follow in a
  spec of their own.

## Summary

A node seats a bounded number of quack clients, and until now it learned it had too many only in
the middle of a query: the door's worker pool shed a socket, and some client's query failed with
`IO Error: Server returned nothing`.

- **Seats.** A quack client now reserves its read-ahead of the door's workers,
  `acl_quack_client_depth` (64). The door seats `acl_quack_server_max_connections /
  acl_quack_client_depth` clients.
- **Refusal at connect.** The next client is refused when it connects, before a session is opened,
  with the reason: `acl: node at capacity - 16 of 16 quack clients seated (...); try another node`.
- **Departures.** A client that disconnects, or whose heartbeat lease runs out, frees its seat, and
  its acl session ends with it instead of idling for 15 minutes.
- **The load report.** `acl_node_load()` reports the numbers admission decides with, and the same
  document is served to an orchestrator on both doors.

## Problem

Measured with `test/bench/door_concurrent.py` (spec 077's concurrency addendum):

- **The ceiling.** The door's pool keeps one thread per keep-alive connection, up to 1024. A quack
  client keeps 64 of them, one per FETCH in flight. The node therefore seats about 16 clients.
- **Past the ceiling.** Some queries failed mid-flight in every run, with or without the fetch window.
- **Lingering sessions.** A client that left kept its acl session until `acl_session_idle_timeout`,
  because quack tells nobody about a disconnect. That counted against `acl_max_sessions`, and it hid
  from tresor's observers (spec 078) that the client was gone.
- **No report.** An orchestrator had nothing to read to route a new session elsewhere.

## Design

**The seat check.** It happens in the server's connect handler, before authentication, through a
`sync.py` patch.

- **Counting.** The handler first sweeps the connections whose heartbeat lease has run out. quack
  notices those only when they send again, so a vanished client would otherwise hold its seat
  forever. It then counts the connections still alive.
- **The claim.** An `AclQuackSeatClaim` asks `AclQuackAdmit` about the seated clients plus the ones
  already between their own check and the creation of their connection. That pending count is kept
  under a lock on the store. Without it, a burst of connects all passed the check at once: 18 of 16
  in the bench. The claim lives for the handler's scope and is released when the connection is
  created or refused, including on an exception.
- **The refusal.** It is audited as `session refused` with `at_capacity`, like the session cap's.
- **Turning it off.** `acl_quack_client_depth = 0` turns seat accounting off, leaving the pool as
  the only bound.
- **The settings' scope.** Both settings are read when a client connects. The pool's own cap is
  fixed when the door is served, so a new `acl_quack_server_max_connections` binds the pool only
  after the door is served again.

**A departed client ends its session.** Three places call `AclQuackConnectionGone`, which ends the
acl session bound to that connection through `SessionEndBound`, the binding `acl_quack_authenticate`
made:

- the server's DISCONNECT handler, with reason `client`;
- the connect-time sweep, with reason `idle`;
- the lease-expiry path of `RenewConnectionLease`, also with reason `idle`.

The session's close event and spec 078's observers see the end at once.

**The load report.** `NodeLoadJson(db, store)` returns:

```json
{"draining":false,
 "sessions":{"live":2,"max":1000,"by_door":{"flight":0,"quack":2,"session":0}},
 "quack":{"slots":1024,"per_client":64,"seats":16,
          "doors":[{"uri":"quack:localhost:8815","seated":2,"seats_left":14}]},
 "admit":{"new_session":true,"new_quack_client":true}}
```

It is served in three ways:

- **SQL.** `acl_node_load()` is the operator's. Like every `acl_` function, a principal is denied it.
- **Quack.** `GET /.well-known/acl-node` on the quack listener.
- **Flight.** The Flight Handshake payload `node-load`, next to `discover-auth`, because
  FlightSqlServerBase seals DoAction.

The last two are served only while `acl_metrics_endpoint` is on, the same switch as `/metrics` (the
owner's decision 2). Otherwise quack answers 404 and Flight answers `NotImplemented` "the load report
is off". The report carries counts and states only, never a handle, principal, role or object name.

`seated` in the report is the door's live connection count. A lapsed connection disappears from it
at the next connect's sweep, so the report can briefly show a seat that the next connect will free.

## Enforcement & security

This is not an enforcement feature, but it changes what an unauthenticated caller can learn.

- **Before authentication.** The capacity refusal precedes authentication, so it opens no session
  and costs no JWKS read. It also tells an unauthenticated client that the node is full. That is the
  same information an orchestrator is meant to read, and what a draining node's discovery answer
  (503) already says.
- **The report.** It is opt-in, with the same exposure as `/metrics`.

## Testing

- **`test/sql/integration/acl_quack_seats.test`.** With a depth of 512 there are two seats. It
  checks:
  - with no door, the report has no doors and admits no quack client;
  - with two clients attached, the report says 2 of 2 and `new_quack_client` false;
  - the third ATTACH is refused with the reason, and the refusal is counted under `at_capacity`;
  - the seated clients keep reading;
  - `DETACH` frees the seat and ends that client's session, so the report shows 1 seated and 1 quack
    session;
  - the next ATTACH is seated;
  - `acl_drain()` turns `new_session` false;
  - a depth of 0 turns the accounting off.
- **`test_acl_quack_embed`.** `GET /.well-known/acl-node` answers 404 while the switch is off and the
  document while it is on. The document names the door and its 16 seats, is identical to
  `acl_node_load()`, and names no identity.
- **`test/e2e/flight/auth.sh`.** The `node-load` payload is refused while the switch is off. With it
  on, it answers a report that admits a new session, counts sessions per door, and names no
  principal.
- **The bench.** `door_concurrent.py` with 24 clients, three runs: every failure is an explicit
  refusal at connect ("16 of 16"), 7 or 8 per run. There is no mid-query shed and no 30 s stall, and
  every seated client answers correctly.

## Alternatives considered

- **Counting acl sessions instead of the door's connections.** Rejected: sessions outlive their
  clients until the idle timeout, and 16 one-shot `quack_query` calls would fill a node for a
  quarter of an hour.
- **Checking after authentication.** Rejected: a refused client would leave an open session behind.
- **Measuring each client's real read-ahead.** Counting sockets per session only works after the
  client has connected, which is too late to refuse cleanly. The server-announced read-ahead
  (duckdb-quack #277) is the real fix, and until then the reservation is an assumption.

## Follow-ups

- **Design 076 P1b.** The node's stream-memory budget and the bounded wait of a sticky session's
  statement.
- **P2.** A server-announced read-ahead, which would make the reservation the window (#277).
- **Pre-existing, found here.** An instance that exits without `acl_quack_stop` crashes at process
  exit. The process-wide registry of doors holds the server, whose connections hold the instance,
  so the instance is destroyed only by the static destructors. There httpfs's client destructor
  throws on a mutex already gone: `mutex lock failed: Invalid argument`. This is spec 063's
  "a server outlives its instance", and it wants an instance-close hook that stops the doors.
