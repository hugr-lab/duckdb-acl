# Spec 078: the acl_connection contract, acl's side — a statement's session, and session open/close

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: hugr-lab
- **Contract**: duckdb-ext-common spec 005, `contracts/acl_connection.hpp` (magic `ACLC`, version 1),
  shipped in v0.4.0. Consumer: tresor's delegation.

## Summary

tresor resolves secrets for a user's session through a delegation grant, not as the node. For that it
needs two things from acl.

- **The session behind a statement.** While a statement runs under a session, the connection names
  that session.
- **Session opens and ends.** When a session opens, tresor needs the verified token once, to
  exchange it for a grant. When the session ends, it needs a signal to revoke the grant.

acl now provides both through the shared contract:

- **`AclConnection`.** acl publishes the session for the duration of every statement that runs under
  `ACL SESSION`.
- **`AclSessionHooks`.** acl calls the registered `SessionObserver`s on every open, with the token by
  reference for the duration of the call. It calls them exactly once on every close, after the open,
  whatever ended the session.

## Design

### The statement's session, on its connection

- **Where.** The override already leaves a note per decided statement (spec 074), and
  `AclProfileState`'s `QueryBegin` takes it onto the connection. That note now also carries the
  session's `opened_at` and `expires_at`, read from `SessionRefOf`.
- **Publish.** When the note names a session (`proto.session`, set only by `ACL SESSION`),
  `QueryBegin` publishes an `AclSessionView` on `AclConnection`. The view holds the ops id, the
  principal, the door, the open and expiry times, and the statement's trace markers.
- **Withdraw.** `QueryEnd` takes the view off in every case: a statement that succeeded, one that
  failed, and one that was interrupted. A statement that runs under no session also takes it off.
- **Why only per statement.** A gateway's shared connection carries many principals (spec 068), and
  the next statement may be another principal's. Between statements nothing is shown. A door's own
  connection gets no special case, because every door statement carries its `ACL SESSION` prefix. The
  quack door composes it in `acl_quack_authorize`, and the Flight door in `SessionSql` for its
  reservations, whose note is set on the connection with `SetConnectionProfileNote`.
- **What the view never holds.** It has no handle. Principal claims are the verified token's, as
  every rewrite already sees them.

### Opens and closes

`SessionNotifier`, in `acl_session_hooks.{hpp,cpp}`, is a member of the store.

- **Open.** `SessionOpenBody` marks the session as opening with `BeginOpen`, under the store's lock,
  right before inserting it. `SessionOpen` then calls every observer's `OnSessionOpen` outside the
  lock, before the handle is returned, with `SessionOpenInfo` and the token by reference. The info
  carries the id, the principal, the door, `token_issuer` (the JWT's `iss`), `opened_at` and
  `expires_at`.
- **Close.** Every removal of a session record already goes through `SessionClosed`, which is also
  where the close audit event comes from. It now queues the close with `QueueClose`. The reason is
  the one the audit uses: `client`, `idle`, `expired`, `killed` or `door_stopped`. A close that
  arrives while its session's open is still being delivered waits until the open has gone out.
- **Delivery.** Every public method that can end a session declares `DeliverSessionNotices` before
  its lock guard, so the queue is flushed after the lock is released. Those methods are
  `SessionOpen` (its sweep), `SessionPrincipal`, `SessionSweep`, `SessionKill`, `SessionClose`,
  `SessionBind` and `SessionCloseAll`. Observers are therefore never called under acl's locks, and
  an observer that calls back into acl cannot deadlock it.
- **Shutdown.** The store's destructor closes the sessions still open, with reason `shutdown`.
- **A failing observer.** An observer that throws is counted and dropped. It never fails an open or
  a close. A call longer than 100 ms is counted as slow. acl cannot pre-empt an observer, because a
  token reference must not outlive the call. tresor does its exchange asynchronously, so the
  connect does not wait on the IdP.
- **Gauges.** `acl.sessions.observers` is the number of registered observers, or -1 when the
  instance's registry speaks another contract version. `acl.sessions.observer_failures` and
  `acl.sessions.observer_slow` count the failed and slow calls.
- **Another contract version.** A registry stamped with another version is refused. acl then calls
  nobody, sets the gauge to -1, and writes the reason as a `policy` event `contract_mismatch`.

## Enforcement & security

- **The token.** It crosses only as a reference during `OnSessionOpen`. acl stores it nowhere new:
  the session record never held it. The test checks that it appears in no listing and no audit event.
- **The handle.** It never crosses. The contract carries only the ops id.
- **Other principals.** Per-statement publication means a statement never sees another principal's
  session on a shared connection.
- **What an observer can do.** It can learn who opened a session. It cannot change the decision, the
  principal or the session.

## Testing

`test/cpp/test_acl_session_hooks.cpp` plays the consumer and reaches every object through the
contract header. acl is linked statically into the libduckdb it uses. It checks:

- **The open.** It reaches the observer with the ops id that `acl_sessions()` lists, never the
  handle. It carries subject, issuer, `token_issuer`, door, `opened_at` and `expires_at`, and the
  token, compared during the call.
- **`AclConnection` around statements.** It shows nothing before a statement and the whole session
  during one. It shows the session in each statement of a batch. It shows nothing after a statement,
  after a failed statement, and for `ACL TOKEN`, which has no session.
- **Close reasons.** `client` from `acl_session_close`, `killed` from `acl_session_kill`, `idle` from
  the idle timeout and a sweep. There is one open and then one close per session.
- **A throwing observer.** The session opens regardless, and the gauge counts the failure.
- **Shutdown.** Destroying a second instance closes its session with `shutdown`, and the first
  instance's observer hears nothing of it.
- **Stamps.** A registry or state stamped otherwise is refused by `Reach`. acl's own refusal path
  cannot be staged in this binary, because static acl reaches the registry when the instance is
  created. It is the six lines at load, reviewed.
- **A real door.** A quack client's statement, run through the embedded door, shows the door's
  session with door `quack`. The observer heard its open, and stopping the door closes it.

## Alternatives considered

- **A session-long state on door connections.** Rejected: every door statement carries the prefix,
  so publishing per statement covers the doors too. One mechanism is less to get wrong, and it is
  the only safe one on a gateway's connection.
- **Queued, asynchronous delivery of opens (R8's shape).** Rejected: the token would have to outlive
  the call. The consumer makes its own work asynchronous instead.
- **An observer that can veto a session open.** Not wanted by the consumer. Failing closed at secret
  lookup is enough, and a veto would make an IdP outage take a door down.

## Follow-ups

- tresor's consumer side: the grant, the lookup, failing closed, and the e2e (tresor's own spec).
- acl-otel may re-pin to v0.4.0 at leisure. `ACLA` is unchanged.
