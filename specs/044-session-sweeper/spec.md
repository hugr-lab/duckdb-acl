# Spec 044: sessions that end when nobody ends them

- **Status**: implemented
- **Date**: 2026-08-22
- **Author**: hugr-lab

## Summary

Spec 040 left one thing open and named it plainly: nothing sweeps abandoned sessions. A record is
erased when it is closed, and when it is next looked up past its `exp` — and never otherwise. This adds
the three things that turn that from a note into a bound: an **idle timeout**, so a session nobody uses
dies whatever its token says; a **sweep**, so dead records go without being asked for; and a **cap**, so
the map cannot grow without limit. It also closes a leak found while writing it — re-authenticating a
connection orphaned its previous session rather than ending it.

## Problem

Three ways the session map grows and never shrinks, all reachable today:

- **A client that connects and vanishes.** quack calls the authentication function per connection and
  nothing on disconnect, so every connection mints a session that only its own next use would clean up
  — and there is no next use. Connection churn is therefore a memory leak, and the door is exactly the
  component that sees churn.
- **A token that outlives the client.** Expiry is judged from the token's `exp`. A long-lived token —
  the test fixtures use one valid until 2100, and real deployments issue days — means the record
  survives long after the client is gone. `exp` bounds a *credential*; it says nothing about whether
  anyone is still there.
- **Re-authentication.** `SessionBind` replaces the connection's binding but leaves the session it
  displaced in the map, unreachable and permanent. Reading the code rather than guessing: the handle is
  simply overwritten in `session_bindings`, and nothing erases the old one from `sessions`.

None of these is a security hole — an orphaned session is unreachable, since the handle is never handed
out again and the binding is gone. They are a resource bound nobody set, on the component most exposed
to arriving strangers.

## Design

**A session gains a `last_used`**, set when it is opened and updated every time it is resolved. Two
rules end a session, and either is enough:

- its token's `exp` has passed (as today, with `acl_jwt_clock_skew`);
- it has not been used for `acl_session_idle_timeout` seconds (default 900; `0` turns the rule off).

The idle rule is the one that matters for the door: it does not care what the token claims, only whether
anyone is still there.

**A sweep drops every dead record in one pass**, and the bindings that point at them. It runs:

- explicitly, through `acl_session_sweep()`, which returns how many it removed — an operator's tool, and
  what the tests use so that sweeping is observable rather than inferred;
- automatically inside `SessionOpen`, at most once every 60 seconds or whenever the map is at its cap.
  The operation that grows the map is the one that pays to clean it — no thread, nothing to shut down,
  and no cost on a quiet instance.

**A cap bounds it: `acl_max_sessions` (default 10000; `0` = unlimited).** At the cap, `SessionOpen`
sweeps first and refuses if the map is still full. Refusing rather than evicting is deliberate: evicting
the oldest would let an arriving stranger end an active client's session, which is a worse failure than
being told to try later. A door turns the refusal into "Authentication failed", which is already what a
client handles.

**Re-authentication closes what it displaces.** `SessionBind` ends the session the connection was bound
to before binding the new one.

**`acl_session_count()`** reports how many are live. Both new functions are denied to a principal, like
the rest of the session surface (spec 040) — a client may not learn how many others there are, nor sweep
them.

## Enforcement & security

- **Nothing here widens access.** Sweeping and capping only ever *end* sessions; the failure mode of a
  bug in this code is a client asked to reconnect, never a client admitted.
- **The cap is a fail-closed bound, and it can be used to lock others out.** An attacker who can
  authenticate can fill the table and make the door refuse everyone until the idle timeout drains it.
  That is a real trade, taken knowingly: the alternative — evicting to make room — lets the same
  attacker end *existing* sessions, which is worse. The mitigation is the idle timeout, which keeps the
  table small enough that the cap is a backstop rather than a limit reached in practice.
- **A swept session is indistinguishable from an expired one** to a client: both give NULL from
  `acl_session_sql` and a refusal from the prefix. Spec 040's follow-up about telling a client *why*
  still stands, and this adds a third reason to it.
- **Per instance, under the same lock** as the rest of the store. The sweep is O(n) in the map, run at
  most once a minute, so it cannot become the thing that serialises a busy door.

## Testing

`test/sql/acl_session.test` — the parts a `.test` file can reach: `acl_session_count()` follows opens
and closes; `acl_session_sweep()` removes an expired session and says how many; re-authenticating a
connection leaves one session rather than two; the cap refuses a further open and `acl_session_open`
answers NULL; both new functions are denied to a principal.

`test/cpp/test_acl_session_sweep.cpp` — what a `.test` file cannot, because the idle timeout needs time
to actually pass. Three scenarios: the sweep takes exactly the idle session and leaves the one that was
*used* while the clock ran; an idle session is refused on use even before anything sweeps, so a sweep
that never ran cannot leave a dead session usable; and re-authenticating a connection leaves one session
rather than two.

Its margins are wider than they look necessary — a two-second timeout with 1.5s sleeps rather than one
second with 1.4s — and that is the fix for the first version, which failed intermittently: the clock is
whole seconds, so a margin under a second decides the outcome by where the boundary happens to fall.

## Alternatives considered

- **A background sweeper thread.** Predictable, and it costs a thread per instance plus a shutdown
  path, for a job that has a perfectly good trigger already: the operation that grows the map.
- **Evicting the oldest at the cap.** Keeps the door open under pressure, at the price of letting a
  stranger end somebody's session. Wrong trade for an access-control component.
- **Hooking quack's disconnect.** The honest fix for the churn case, and not available: quack calls no
  callback on `DISCONNECT_MESSAGE`. Worth proposing upstream; the sweep is what works without it.

## Follow-ups

- **Shared session backends** (spec 040) will need their own sweeping, and a cluster's cap is a
  different question from an instance's. The rules here are the local case of both.
- **Telling a client why its session ended** — expired, swept, closed, or never existed — is still one
  NULL for all four.
