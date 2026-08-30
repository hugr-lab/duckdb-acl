# Spec 054: telling a client why its session ended

- **Status**: implemented
- **Date**: 2026-08-30
- **Author**: hugr-lab

## Summary

`acl_session_sql(handle, sql)` returns NULL for every unusable session - expired, idle, closed or
never-opened alike (spec 044's follow-up). A client that reconnects needs to tell them apart:
an **expired** token means fetch a fresh one, while **idle**/**closed**/**unknown** mean reopen with
the same token. This adds `acl_session_reason(handle)` -> "live" / "expired" / "idle" / "unknown",
judged read-only so the reason survives the very NULL that prompts the client to ask.

## Problem

The reason existed inside the store (`SessionPrincipal` already computed "unknown"/"expired"/"idle")
but was collapsed to one NULL at every client-facing boundary. Worse, the natural "ask why" flow was
self-defeating: `acl_session_sql` resolved through `SessionPrincipal`, which **erases** a dead session
on read, so a follow-up query would find nothing and answer "unknown" for what was really an expired
session - the one distinction that actually changes what the client does.

## Design

- **`SessionReason(handle)`** in the store: judged read-only (no bump, no erase), the same three
  clock comparisons as `SessionAlive`, returning the reason string. "unknown" covers both a closed
  session and one that never existed - distinguishing them would need a tombstone per closed handle
  (unbounded state) for no actionable difference, since both mean "reopen".
- **`SessionSql` no longer erases.** It now judges inline - composing for a live session (and bumping
  its idle clock, since using a session keeps it alive, spec 044) and returning "" for a dead one
  **without erasing it**. The dead record lingers until the next sweep, which is what lets
  `SessionReason` still report the true reason after the NULL. `acl_session_sql` was rerouted from
  `SessionPrincipal` to `SessionSql` so it stops erasing too.
- **`SessionCount` counts live sessions, not map size.** Now that a dead session lingers until the
  sweep, "how many sessions are live right now" must judge each rather than return `sessions.size()` -
  otherwise a not-yet-swept dead session would inflate the count until the sweep corrected it.
- **`acl_session_reason(handle)`** scalar, registered like the rest of the session surface - denied to
  a principal by the blanket `acl_` gate, available to the door/gateway that holds the contract.
- `SessionPrincipal` keeps its erase-on-read: it is used where the reason is read in the same C++ call
  (the door's `OwnerOf`, `SessionFor`), so erasing there loses nothing.
- **The survives-the-NULL property is single-threaded.** A concurrent `acl_session_sweep()` or a
  `SessionOpen` sweep on another connection may erase the dead record between a client's NULL and its
  `acl_session_reason`, which then reads "unknown" rather than the true "expired"/"idle". This is
  self-correcting and harmless: told "unknown", the client reopens with the same token; if it was
  really expired, `SessionOpen` refuses the stale JWT and the client fetches a fresh one - one extra
  round trip, no wrong outcome.

## Enforcement & security

- `acl_session_reason` is denied to principals (the `acl_` prefix gate), like every other session
  function - a client can learn *its own* handle's reason through the door, never compose or inspect
  another's.
- Read-only judgement leaks nothing a NULL did not already: the reason is a coarse lifecycle state,
  never the token, the principal, or another session's existence (an invented handle is "unknown").
- No behavior a served instance relies on changed except the deliberate one: a dead session is swept,
  not erased-on-touch, and the count reflects live sessions - both observable only to the door's ops
  surface.

## Testing

- `test/cpp/test_acl_session.cpp` (`session-end-reason`): unknown handle -> "unknown"; a fresh session
  -> "live"; an idle session -> `acl_session_sql` NULL then `acl_session_reason` still "idle" (the
  survives-the-NULL property); a closed session -> "unknown".
- `test/cpp/test_acl_session_sweep.cpp`: updated for the new model - resolving an idle session no
  longer drops the record (the reason is still readable), and the sweep is what drops it.
- `test/sql/acl_session.test`: the existing expired-token path now also pins
  `acl_session_reason = 'expired'` after the NULL, plus "live" and "unknown" - the SQL-level proof of
  the reason the cpp test cannot force expiry for.

## Alternatives considered

- **Tombstone closed sessions to distinguish "closed" from "never existed"** - rejected: unbounded
  state (every closed handle remembered) for a distinction that changes nothing (both mean reopen).
- **Return the reason from `acl_session_sql` itself** (a struct, or a second output column) - rejected:
  its contract is SQL-or-NULL and a door already branches on the NULL; a separate read-only function
  keeps that contract and composes cleanly.

## Follow-ups

- None. The four lifecycle states a handle can be in are all reported; the shared-session-backend
  idea that would have complicated this is dropped (nodes are node-local).
