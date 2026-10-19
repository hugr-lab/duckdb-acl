# Spec 135: a session moves between nodes - its context in the cookie, an error only for what cannot move

- **Status**: implemented (accepted by the owner 2026-10-19: «По спекам ок»)
- **Date**: 2026-10-19
- **Author**: Claude (with the owner)

## Summary

Behind the platform's front, a session stays on the node that holds it (spec 134's label). Nodes still go away: a
roll, a drain, a scale-down. Today a client whose node went away is placed on another node. That node does not know
the session, so it opens a new one silently, and the client loses its `USE` without noticing. A short name then
resolves in the MAIN catalog, and the client can read another table, with no error.

Long-lived connections, a federation's above all, run for months and mostly read. The owner, 2026-10-18 (design/082,
F1): a session moves silently when nothing of it is lost, and errors once when something is.

- **The portable context travels in a cookie the node sets: the session's `USE` and its client-local settings.** A
  node that does not know the session restores the context. Each item is judged again, as if the client had sent it.
- **What cannot move sets a pinned flag in that cookie: an open transaction, a temp table, the view-as mode.** A node
  that does not know a pinned session still restores what is portable, refuses the first call once, saying what was
  lost, and serves the client on a new session. A lost transaction stays aborted until the client's ROLLBACK, so no
  part of it runs in autocommit. A session in the view-as mode is not seated afresh unless the call declares the mode.

## Problem

`SessionFor` (`src/flight/acl_flight_door.cpp`) answers a cookie it does not know with a new session bound to the
same cookie. That is right when the session died idle on this node and held nothing. It is wrong whenever the
session held something:

- **`USE`** (spec 114): short names silently resolve somewhere else.
- **A transaction** (spec 055): the client's next `INSERT` runs in autocommit on the new node, and its `COMMIT` finds
  nothing. Half a transaction is applied, silently.
- **Client-local settings** (spec 068): `TimeZone` / `Calendar` render the same timestamps differently. The trace and
  lineage context are lost.
- **A temp table** (spec 050): it is gone. A read of it fails honestly, but the client is not told why.
- **The view-as mode** (spec 120.3): its guard is the node's memory of a session that ended in the mode. Another
  node has no such memory, and its addendum already refuses only what this node remembers.

The front cannot help, and should not. It keeps no session table (spec 134), so only the node and the client know
what the session held.

## Design

### The cookie `acl_session_state`

Both kinds of state go in one cookie, set by the Flight door beside `acl_flight_session_id` and `acl_node`:

```
acl_session_state=<base64url of a JSON object>; HttpOnly; Path=/; SameSite=Strict
```

```json
{"v": 1, "p": "<16 hex digits>",
 "use": {"catalog": "<key>", "schema": "<key>"},
 "set": {"TimeZone": "Europe/Berlin", "acl_correlation_id": "..."},
 "pinned": ["transaction", "temp", "view_as"]}
```

- **`p`**: whose state it is. It is a tag of the principal's fingerprint (the first 16 hex digits of the SHA-256 of
  `PrincipalFingerprint`), never the fingerprint itself. It is required.
- **`use`**: the session's `USE` (spec 114, `Session::use_catalog` / `use_schema`), in canonical keys (spec 116).
- **`set`**: what the client SET on its session from spec 068's allowlist. That list is one list,
  `PORTABLE_SETTINGS` in `acl_session_state.hpp`, and `ClientSettingAllowed` reads it too: `TimeZone`, `Calendar`,
  `acl_metadata_max_rows`, `acl_correlation_id`, `acl_traceparent` and the three lineage settings of spec 107.
  - A value is carried only when the connection holds it at scope `LOCAL` and it differs from what a fresh session
    of the node reads (its GLOBAL, else the option's default). duckdb's `RESET` writes the default as a LOCAL value,
    and the node's own values are never carried. A client that SETs exactly the node's value is not carried, and
    reads the new node's: in one cluster the nodes share their GLOBALs by the profile.
- **`pinned`**: why the session cannot move.
  - `transaction`: an explicit transaction is open on the session's connection. That is duckdb's own word
    (`!IsAutoCommit()`), whoever began the transaction: `BeginTransaction`, SQL `BEGIN`, or a moved one.
  - `temp`: a session temp table exists (spec 050; an ingest's `temporary = true` included).
  - `view_as`: the session views the catalog as a role (spec 120.3).
- **When it is sent:** on the response of the call that changed the state, whenever the state differs from what the
  request's own cookie said, with an error response included. An empty state clears the cookie (`Max-Age=0`).
  - The door reads the state at the end of `UnderSession`, after the call's work, and also after a body that
    throws. It sends the state with `ServerCallContext::AddHeader`. A middleware cannot do this: Arrow sends a
    middleware's headers right after `StartCall`, before the handler runs, so they would describe the state before
    the call.
  - It says nothing on a call where it cannot see the state, so a pin it cannot see is never dropped:
    - the session went away during the call (a kill, a sweep, a swap);
    - the session never ran anything on this node;
    - a statement or a stream's pull holds the connection: the state is read with `try_lock`, and that other call's
      own response carries the change.
- **Bound:** at most 1 KiB encoded, because a request's metadata (a bearer of several KB, and the cookies) shares
  gRPC's 8 KiB limit. A larger state keeps its principal and its pins and adds `context`; it is never written
  partly. 1 KiB of base64 is about 760 bytes of JSON: a session that carries a full lineage context (parent, root,
  job, correlation id, traceparent) and a USE can pass it, and its moves then refuse once, honestly.
- **The decoder** reads at most 4 KiB. It answers UNREADABLE, and never reads partly, on any of: a malformed input,
  an unknown `v`, a wrong type, a missing or empty `p`, a setting not on the list or a setting twice, a key twice, a
  NUL inside a key or a string, or a key this build does not write. So a restore runs at most one `USE` and eight
  `SET`s.
- **Not here:**
  - prepared statements and reservations (spec 047), and open streams (spec 070): on another node they fail with
    their own "unknown" errors, which are honest;
  - the session's resource limits and placement (specs 085/096): they are the principal's, resolved again at open.

### A call whose session this node does not know

`SessionFor` reads `acl_session_state` when the session cookie names no live session here. That holds whatever the
cookie's `acl_node` label says: another node's, this node's (the session died idle or was killed), or none. A swap
(another principal on a live session) is not this case: nothing of the old principal's context is carried, and the
response overwrites the cookie.

1. **No state.** A new session, as before.
2. **Another principal's state.** `p` is not the caller's tag, verified from the token; a token that does not verify
   is refused as `authentication failed`. That is a stolen or shared jar, or the same subject whose roles changed.
   Nothing of the state carries. A pin it states still refuses the call once, and a transaction it states is
   aborted: the caller cannot be the one to finish it.
3. **The view-as mode, not declared by the call.** The connection is not seated afresh: the call is refused with
   `… viewed the catalog as a role and is gone - connect again`, the same rule as the 120.3 addendum's on every
   node. No record is kept: the pin in the client's own jar refuses each call, so a state the client writes never
   grows the node's memory. A client that drops the pin, its own choice, is seated as itself. A call that declares
   `x-acl-view-as` is put in the mode again (DeclaredViewAs) and goes on.
4. **Otherwise** the session is opened (drain, the session cap and placement refuse a move as they refuse any new
   session). Its connection's lock is taken **before** the session is bound to the cookie and held until the
   takeover is done, so a concurrent call on the cookie waits instead of running on a session not yet restored.
   A takeover that does not finish (the call's own view-as declaration refused, a BEGIN that fails, an exception)
   ends the new session, and the next call reads the state again. After the call's own mode is in place,
   `TakeOverState` runs:
   - **The portable part is restored through the client's own paths, pinned or not.** `USE` becomes
     `SET schema = '<catalog.schema>'` (or `SET acl_use_schema`) and each setting a `SET`, under the session's
     prefix, so `RewriteUse` and spec 068's gate judge each item as the client's own statement now.
     - A `USE` that records nothing (`acl_session_use` answering false) counts as not restored.
     - In a declared view-as mode no `USE` is restored: the mode is metadata only.
   - **A lost transaction** is begun on the new connection and aborted (`ValidChecker::Invalidate`), and the door
     answers its statements itself (`MovedTxnGuardLocked`, on every path a client's SQL runs: the query path, the
     update path, ingest, prepare and the prepared executions). duckdb's abort alone would let a `COMMIT` turn into
     a silent rollback, and a node may run with `disable_database_invalidation`.
     - A `ROLLBACK` passes.
     - A `COMMIT` rolls back and is told `… lost its open transaction - nothing of it was committed`.
     - Anything else is refused: `… lost its open transaction - ROLLBACK to go on`.
     - `EndTransaction` ends it whatever transaction id it names, since the id was the other node's, and a commit is
       told that nothing was committed. `BeginTransaction` asks for the rollback first.
     - The catalog RPCs that run SQL on the session's connection fail as duckdb's abort makes them, until the
       ROLLBACK.
   - **An unreadable state** is treated as if a transaction were in it (fail closed): refused once, then aborted
     until the client's ROLLBACK. A rolling upgrade whose newer build writes what an older one cannot read is the
     case this protects.
   - **Anything not carried refuses this call, once, naming all of it.** That covers a pin, an item that did not
     restore, and an unreadable state. The message is `acl: the session moved to another node and lost its open
     transaction (ROLLBACK to go on: nothing of it was committed); the statement did not run, the connection works
     on`, or `… could not restore its USE, acl_metadata_max_rows`, or `… lost its session context`. The client's
     next call works on the new session.

The token is the authority, as on every call. `SessionOpen` verifies it like any new session (spec 059: `exp` is
judged at establishment), so a long-lived connection moves only with a token that is valid now.

### quack

A quack connection authenticates once, at its CONNECT, so a connection id this node does not know cannot be seated.
The door says so: `acl: this connection is not known on this node - connect again`, and for a lease that ran out
but was not swept yet, `acl: this connection's lease ran out on this node - connect again` (two `sync.py` hunks).
hugr_node's federation client reconnects by itself when it holds nothing pinned, and replays its own context; that
is a hugr-node spec. With duckdb/duckdb-quack#297, the state cookie could ride `/quack` responses too (a follow-up).

### The audit

- `session` events:
  - `moved`, emitted only when something was carried; its reason lists the items' names (`USE, TimeZone`);
  - `move_refused`, with reason codes `session_pinned`, `session_unrestorable` or `session_unreadable`; its reason
    names what was lost.
- Never a value. A setting's name comes from the list, never the client's text.
- Counters `acl.sessions.moved{door}` and `acl.sessions.move_refused{door,reason_code}`.

## Enforcement & security

- **The cookie is the client's own context, not a credential.** It is not signed: nodes share no key, and nothing
  in it grants anything.
  - Every item is judged again as the client's own statement. A forged `USE` of a catalog the principal does not
    hold is refused (and the audit shows the rewriter's own refusal); a setting outside the list is unreadable.
  - Another principal's state carries nothing (the tag), so a stolen jar gives the thief none of the victim's
    context, and the victim's pins do not refuse the thief.
  - A client that drops `pinned` loses only its own transaction or temp tables, its own choice.
  - A client that drops `view_as` runs as its own principal, the administrator itself: view-as is a self-restriction,
    never a grant.
- **The session id stays the bearer secret.** `acl_flight_session_id` is unchanged; the state cookie carries no
  handle and no token, and its tag is one-way.
- **Nothing is silently changed.** A context that is not carried whole is named in a refusal, once, and a lost
  transaction cannot be half committed.
- **Bounded.** A restore is at most nine statements; the cookie is at most 1 KiB written and 4 KiB read.
- **The parameter golden rule is untouched.** Restoring runs the door's own statements on the session's connection,
  as spec 068's `SetSessionOptions` does.

## Testing

- **C++ (`test/cpp/test_acl_session_state.cpp`):**
  - the codec round-trips, escapes included;
  - past the bound, the principal and the pins are kept and `context` is added;
  - a valid state past 4 KiB is not read;
  - every malformed shape reads as unreadable: no principal, a setting off the list or twice, a NUL, a wrong type,
    an unknown key or version;
  - the one settings list.
- **Flight (`test/e2e/flight/run.sh`, its client's cookie jar now a real one).** A "move" is simulated on one node by
  `acl_session_kill` (asserted to kill at least one session): this node no longer knows the session, and the client
  keeps its cookies. Each case:
  - `USE c.stage` and `SET TimeZone`, kill: a short name resolves in `c.stage`, and a `TIMESTAMPTZ` comes back in
    the zone. The `moved` event names `USE, TimeZone`, and no event carries a value.
  - Another principal's token with the jar: nothing carried.
  - A forged `USE` of an unheld catalog: refused naming the USE. The audit holds the rewriter's own "is no catalog
    of the principal", and the next call works.
  - A forged setting outside the list, and a garbled cookie: "lost its session context", once.
  - `acl_metadata_max_rows` above a lowered node bound: "could not restore its acl_metadata_max_rows".
  - `BEGIN`, a write, kill. The next write is refused once, the pin stays in the cookie (decoded), and the write
    after is refused by the door. ROLLBACK goes through, no write of the transaction is committed, and the pin goes.
  - `BEGIN`, a write, kill, a ping that spends the refusal, then `COMMIT`: the COMMIT is told nothing was committed,
    and nothing is.
  - A forged setting and a garbled cookie are held aborted until ROLLBACK, then the connection works.
  - A temp table: refused once, then the connection works.
  - A view-as pin without the header: refused, and refused again; with the state cookie dropped, seated as itself
    (no node record).
  - A drain refuses the move as any new session; the state survives and is restored after the resume.
  - A session that died idle here takes the same path, through the binding that still names it.
  - The counters count each kind.
- **quack (`test/cpp/test_acl_quack_embed.cpp`):** a connection attached before the door restarts gets the door's
  sentence, and attaching again reads.

## Alternatives considered

- **A loud refusal of any unknown session** (design/082 F1 as first written). That breaks every long-lived read-only
  connection on each roll.
- **Refusing a lost transaction once and moving on** (this spec's first build). A driver can spend the one refusal
  on a close or a metadata call and run the rest of the transaction in autocommit. So the transaction is aborted,
  and the door answers its statements: duckdb's abort alone makes a COMMIT a silent rollback.
- **Remembering a moved view-as connection on the node** (`view_as_ended`, as 120.3 does for a session that ended
  here). A client writes that state: any principal could grow the node's memory with ids of its choosing.
- **Pinning only the sessions with state, and letting the front re-place the rest.** The front has no session table
  and should not get one.
- **A signed cookie.** Signing needs a key shared by the nodes, and the cookie grants nothing. Re-judging every item
  is the check.
- **Sharing sessions between nodes** (a session backend). Nodes are isolated by design. A moved session is a new
  session with its context carried, never the old one resumed.

## Follow-ups

- hugr-node: the federation client's reconnect, with its portable context replayed.
- quack: the state cookie on `/quack` responses once duckdb/duckdb-quack#297 is in.
- A ticket the old node issued reads, on the new one, as an unknown ticket, and its audit records it as a foreign
  ticket. It could say "after a move".
- A swap (another principal's token on a live session) still ends the old principal's transaction and temp tables
  without a word to anyone, as before this spec.
- Concurrent calls of one session: the cookie is last-writer-wins, so a response that read an older state can land
  after a newer one. The next call heals it.
- hugr-platform 002 (the front): no change is needed (label → node, gone → any node of the group); its check of a
  move joins the demo.
