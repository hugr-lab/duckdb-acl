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
nothing to learn from a token the node will not seat — while it is set (one exception since the
addendum below: one cookie-less call of a principal who holds the node's own rights). That one refusal covers both
doors and the gateway contract with no per-door state machine, and it fails closed: a door that
forgot to check still cannot seat a client.

The doors additionally check the flag at their own establishment points, only to say *why*:

- **Flight**: `SessionFor`'s fall-through to `SessionOpen` (a new client, or a re-authentication as
  a different principal) answers `Unavailable: acl: node is draining - not accepting new sessions`
  instead of the generic authentication failure. A resolving cookie session is untouched — and a
  re-authentication as a *different* principal is refused **before** the old session is closed
  (the review's finding): that path is a swap, close-then-open, and refusing only the open would
  leave the close behind — drain ending a session, which it never does. The
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
  decide with the result, and the early refusal keeps the drain path free of JWKS reads (but for a
  cookie-less Flight call, whose exception needs the principal: the addendum).
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
- **Flight e2e** (`test/e2e/flight/drain.sh`): a durable-cookie client keeps querying across the
  drain; a second client connecting during drain is refused with the draining message; the seated
  connection re-authenticating as a different principal (a session swap) is refused *and its
  original session survives the attempt*; after `acl_resume()` a new client connects.

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

## Addendum (2026-10-20): the node's own rights are seated, call by call

- **Status**: implemented (the owner's decision of 2026-10-20: "из консоли нужно иметь возможность оператору
  кластера вернуть ноду, которая в drain"; the addendum accepted the same day).

**Problem.** Since spec 118 a drain and its end are an operator's acts from a session of the operator's own
(`DRAIN NODE` / `RESUME NODE`, `platform.drain` / `platform.resume`, the `operate` bundle), and a console acts on a
node only that way (hugr-platform spec 003: every action runs under the person's own token, on the person's own
session there). A draining node seats nobody new, so the only person who can resume it from a console is the one who
still holds a session on it - and nobody does once that session idled out, its console restarted, or another operator
drained it. What is left is the node's own connection (`kubectl exec`), or a restart of its pod: the drain's own right
locked out of the node it drains.

**Design.** A draining node seats **one call** of a principal **who holds the node's own rights** - whom the
platform's authorizer lets read a view of the node's (`PlatformViewClass::NODE`: `node_load`, `sessions`,
`audit_events`, ... - the `observe` bundle, a point grant on one) or call one of its operations (`PlatformRight::
OPERATE`: `kill_session`, `drain`, `resume`, the tracing ones - the `operate` bundle, a point grant on one; a deny wins,
as everywhere) - and nothing else new (`MayOperateNode`). What the seated call may then do is the authorizer's, as on
any node: an observer watches the drain, an operator ends its stragglers, whoever may resume it resumes it (the owner,
2026-10-20: "видеть нагрузку и сессии и если есть права то и грохнуть сессии вручную, что бы ускорить дренаж"). The rule
is `SessionOpen`'s (`per_call`), and the one kind of session it applies to is the Flight door's per-call session (spec
050): a call without a cookie, whose session closes on its way out.

- A connection-long session - a client that keeps the door's cookie (a driver; its DoGet carries the cookie its
  GetFlightInfo was handed), a quack connection, the gateway contract's `acl_session_open`, a swap - is refused before
  anything is verified, whoever asks: a driver or a front's client of an operator's goes elsewhere, and nothing new
  holds the drain (`acl_drain()`'s count, the agent's stop). The Flight door's refusal of one now comes from
  `SessionOpen` like quack's and the contract's, so it is a principal-less `session refused` event (`draining`) too,
  where the door's own early answer recorded nothing.
- `acl_drain()` answers what remains to be drained: a session of the calling call (a console's `DRAIN NODE`) ends with
  it and is not counted, so the watch loop reaches 0 from a console too; `platform.sessions` and `node_load` leave it
  out as well (a console's read is nobody connected to the node).
- A draining node hands out no session cookie. With one, a client that keeps the door's cookie (a driver) would carry it
  on the DoGet of a statement its GetFlightInfo already ran (a write, a management statement): a connection-long
  session, refused - the client told "draining" for what ran, and retrying it elsewhere. Without one it stays
  cookie-less on that node, each call its own session; a cookie it brings is refused as before.
- A read is two calls: its GetFlightInfo, seated by this rule, and its DoGet, which redeems the ticket by its bearer
  (spec 134's addendum) - the console's load report of a draining node rides both.
- What a seated call starts it finishes on its connection after its session record closes (a DoGet stream pulls past
  the handler), so the drain's count does not see it and a node's stop cuts it, as for any cookie-less client.
- For a call without a cookie the node verifies the token first: the exception needs the principal. One without the
  node's rights is refused with the drain's code (`session refused`, `draining`); a token that does not verify, with its own
  (`principal`, or the keys' source's), on the node's record - and in both cases the Flight door answers the drain's
  sentence, so a front still reads UNAVAILABLE "draining" for a cookie-less call and re-seats it. A node of another
  resource group refuses an operator as it would anywhere and says so (spec 096's sentence and trailer), never as a
  drain.
- The seated call's `session` event says it was seated while draining, and is a decision of the audit's (on record at
  the default level `decisions`, where an ordinary `opened` is `all`'s).
- Nothing else of the drain changes: the password handshake (spec 064) stays refused (it only seats new clients through
  an IdP grant), quack's discovery still answers 503, a principal without the right still cannot call the drain
  functions.

**Why one call.** A console (hugr-platform spec 003) acts on a node with calls of the person's token and no cookie, so
it holds no session on any node; the first form of this addendum seated a connection-long session for an operator,
and the reviews found what that does: a console's rights lookups and its Cluster page left an operator's session on
every draining node they touched, a front routed an operator's driver back to the draining node its cookie named, a
pod being stopped waited for them until its deadline. A call that ends its session ends all of it.

**What it costs.** A cookie-less call to a draining node costs one token verification (the keys are cached) and a read of
the principal's rights and role claims from the policy (cached by role); the fronts route new connections to admitting
nodes, so such calls are a console's or a pinned cookie-less client's.

**What is not new.** The connection-long refusal reads the token first on spec 135's path (a cookie with a session
state: the state's principal tag is matched against a verified token before the drain is reached), and spec 134's
redeem path seats any verified principal for a cookie-less DoGet, its reservation judged inside - both older than
this addendum. Found beside it, and kept (the owner, 2026-10-20): a held prepared statement keeps the rights it was
prepared with (spec 047's reservation stores the bound statement) - as an open connection to a managed database keeps
its session; a revoke refuses every new statement and session (a fresh `ACL NATIVE` after it is refused), and under
`acl_session_token_binding='every_use'` the token's `exp` ends the handle's session too.

**Security.** No new authority: the call goes only to a principal who could act on the node through a session it
already held, and what it may do there is judged by the authorizer that judges every statement. A cookie-less caller
learns from the answer whether its token holds the node's rights (seated or "draining"; a token that does not verify
reads "draining" too) and, for an operator, its placement - nothing a serving node does not tell it.

**Tests.** `test/sql/acl_drain.test`: while draining, the contract's session (`acl_session_open`) is refused to an
operator, a point grant on resume, a deny and a forged token alike, refused before verifying (the drain's code).
`test/e2e/flight/drain.sh`: a cookie-keeping operator's management call is answered and no session cookie handed out;
a cookie it brings is refused; the load report and the sessions list leave the call's own session out; a point grant
on resume is seated, the observe bundle reads the load report, operate with a deny on resume ends a session and its
`RESUME NODE` is refused as denied; the policy bundle alone and a forged token read "draining"; the seats are on record
at `decisions`; `DRAIN NODE` does not count itself; an operator's `RESUME NODE` serves the node again.
`test/e2e/flight/admin.sh`: the operate bundle drains the node, the analyst is refused, the operator's call resumes
it, a second finds it serving.

**Found 2026-10-20 (spec 140's CI): the call's own session was named after its GetFlightInfo.** A cookie-less
client's read is two calls, each with its own session:

- **The statement** is prepared at GetFlightInfo, and the reservation keeps the override's note. That note names the
  GetFlightInfo's session, which ended with that call.
- **Its DoGet** submits the statement, which runs on the workers, and the note put back on the connection named that
  ended session to the statement's `AclConnection`. `CallOwnSession` found no live per-call session by that id, so
  nothing was left out.
- **The test passed by timing.** It passed only when the DoGet's own session closed (the handler returned) before a
  worker computed the report; otherwise the report counted 2 where 1 was right. drain.sh failed about one run in
  eight.

Now the execution is named after the call that runs it: the DoGet's own session, live (`ArmProfile` puts the
caller's session on the reservation's note). The count is right in either order, and drain.sh ran 20 of 20. The
same naming serves a secrets service that acts for the session (spec 078), which used to see an ended one there.

**Left open.** A drain waits for every live session up to its orchestrator's deadline, an idle client's too; whether it
should not wait for an idle session with nothing pinned (spec 135 moves it to another node) is its own spec.

## Follow-ups

- The Flight door's registry holding `DatabaseInstance &`: make an instance closed under a listening
  door refuse like quack's does, instead of relying on stop-before-close.
- Live in-flight *statement* observability (active reservations / running requests per door) if
  watching the session count proves too coarse in practice.
- The shared session backend a cluster needs (spec 040 follow-up) would make drain state per-node
  while sessions roam; drain stays per-node by design.
