# Spec 135: a session moves between nodes - its context in the cookie, an error only for what cannot move

- **Status**: draft
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
  that does not know a pinned session refuses the first call once, saying what was lost. It then serves the client on
  a new session.

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
{"v": 1,
 "use": {"catalog": "<key>", "schema": "<key>"},
 "set": {"TimeZone": "Europe/Berlin", "acl_correlation_id": "..."},
 "pinned": ["transaction", "temp", "view_as"]}
```

- **`use`**: the session's `USE` (spec 114, `Session::use_catalog` / `use_schema`), in canonical keys (spec 116).
- **`set`**: what the client SET on its session from spec 068's allowlist (`ClientSettingAllowed`): `TimeZone`,
  `Calendar`, `acl_metadata_max_rows`, `acl_correlation_id`, `acl_traceparent`, and the lineage context of spec 107.
  Only values the client set itself are listed, never a node's defaults.
- **`pinned`**: why the session cannot move.
  - `transaction`: an explicit transaction is open on the session's connection, whether begun by `BeginTransaction`
    or by SQL `BEGIN` (spec 055).
  - `temp`: a session temp table exists (spec 050; an ingest's `temporary = true` included).
  - `view_as`: the session views the catalog as a role (spec 120.3).
- **When it is sent:** on a response whenever the state differs from what the request's own cookie said. The door
  reads the state after the call's work, when the response's headers go out. An empty state clears the cookie
  (`Max-Age=0`).
- **Bound:** at most 3 KiB encoded. A larger state is never written partly: the cookie carries `pinned:
  ["context"]` instead, and a move errors honestly.
- **Not here:**
  - prepared statements and reservations (spec 047), and open streams (spec 070): on another node they fail with
    their own "unknown" errors, which are honest;
  - the session's resource limits and placement (specs 085/096): they are the principal's, resolved again at open.

### A call whose session this node does not know

Before `SessionOpen`, `SessionFor` reads `acl_session_state`. That holds whatever the cookie's `acl_node` label says:
another node's, this node's (the session died idle or was killed), or none.

1. **No state cookie:** a new session, as today.
2. **A state that is pinned** (or unreadable: malformed, a `v` this build does not know): the new session is opened
   and bound to the cookie as today, but this call is refused with `Invalid`.
   - The message: `acl: the session moved to another node - its open transaction / temp tables / view-as mode are
     gone; the statement did not run, the connection works on`. It names what the state listed.
   - The response clears the state cookie.
   - The client's next call finds the new session live, and goes on.
   - `Invalid` is what spec 120.3's guards answer: a driver neither retries it nor reads it as bad credentials.
3. **A state that is not pinned:** the new session is opened, and the context is restored before the call runs,
   through the same paths a client's own statement takes.
   - `USE` goes through `acl_session_use`, which judges the catalog and schema against the principal (spec 114).
   - Each setting is a `SET` on the session's connection (spec 068's path, with its validators: spec 109's run-ref
     check, spec 119's refused raise).
   - If any item does not restore (the catalog is no longer held, a value is refused), the call is refused as in 2.
     The message names that item. Silently dropping a `USE` is exactly the bug this spec closes.

The token is the authority, as on every call. `SessionOpen` verifies it like any new session (spec 059: `exp` is
judged at establishment), so a long-lived connection moves only with a token that is valid now. A client refreshes
it. Drain (spec 066), the session cap (spec 044) and placement (spec 096) refuse a move as they refuse any new session.

### quack

A quack connection authenticates once, at its CONNECT. Later requests carry the connection id but no token. So a
node that does not know a connection id cannot open a session for it, and a move is always the client's reconnect.

- The door answers an unknown connection id with a reason a client can recognise: `acl: this connection is not known
  on this node - connect again`. This takes one `sync.py` hunk around quack's own lookup; the text is the door's.
- A client that knows it holds no pinned state reconnects by itself. hugr_node's federation client knows that, since
  it issued its own `USE` / `BEGIN` / `CREATE TEMP`. It replays its portable context on the new connection. That is a
  hugr-node spec; nothing here changes the quack client.
- With duckdb/duckdb-quack#297 the client keeps cookies per logical connection. The door may then set
  `acl_session_state` on `/quack` responses too, and a generic client could act on it. That is a follow-up, once #297
  is in.

### The audit

- `session` events:
  - `moved` (door, `restored` = the items carried) when a new session took a context over;
  - `move_refused` (door, `lost` = what the state listed or the item that did not restore).
- Never the values themselves: a setting's name, not its value; a `USE` as the catalog's key, which the audit
  already notes for resolved objects (spec 116).
- Counters `acl.sessions.moved` and `acl.sessions.move_refused`.

## Enforcement & security

- **The cookie is the client's own context, not a credential.** It is not signed: nodes share no key (keys come by
  discovery, nothing is baked in), and nothing in it grants anything.
  - Every item is judged again as if the client had sent it now. A forged `USE` of a catalog the principal does not
    hold is refused (case 3), and a forged setting goes through the same allowlist and validators as a `SET`.
  - A client that drops `pinned` loses only its own transaction or temp tables, its own choice.
  - A client that drops `view_as` runs as its own principal, the administrator itself: view-as is a self-restriction,
    never a grant. A call that declares the mode (`x-acl-view-as`) is put in it again, as today.
- **The session id stays the bearer secret:** `acl_flight_session_id` is unchanged. The state cookie carries no
  handle and no token.
- **Nothing is silently changed:** a context that cannot be carried whole is an error, once (case 2 or 3).
- **The parameter golden rule is untouched.** Restoring runs the door's own statements on the session's connection,
  as spec 068's `SetSessionOptions` does.
- **The cookie's size is bounded**, and so is its decode. Malformed input is refused once, never parsed partly.

## Testing

- **C++ (`test/cpp/test_acl_session_state.cpp`):**
  - the cookie codec round-trips;
  - the bound gives `pinned: ["context"]`;
  - malformed input (bad base64, bad JSON, an unknown `v`, wrong types) reads as unreadable;
  - the pinned set is computed from a session record and a connection's state.
- **Flight (`test/sql` door tests and `test/e2e/flight/`).** A "move" is simulated on one node by
  `acl_session_kill` (this node no longer knows the session; the client keeps its cookies), then:
  - `USE c.s`, kill, then a short name: it resolves in `c.s` (a `moved` event);
  - `SET TimeZone`, kill: the timestamp renders in that zone;
  - `BEGIN`, kill: the next call is refused once, naming the transaction; the one after succeeds on a new session;
  - a temp table, kill: refused once, naming the temp tables;
  - view-as, kill: refused once;
  - a state whose `USE` names a catalog the principal does not hold: refused, naming it (a negative test of the
    forged cookie);
  - a malformed or oversized cookie: refused once;
  - a move while the node drains: UNAVAILABLE, as for any new session.
- **quack:** an unknown connection id gets the door's sentence.
- **hugr-platform's demo** gains a check once the front (hugr-platform 002) is in: a read-only session survives its
  node's roll, and a session in a transaction is told once.

## Alternatives considered

- **A loud refusal of any unknown session** (design/082 F1 as first written). That breaks every long-lived read-only
  connection on each roll.
- **Pinning only the sessions with state, and letting the front re-place the rest.** The front has no session table
  and should not get one.
- **A signed cookie.** Signing needs a key shared by the nodes, and the cookie grants nothing. Re-judging every item
  is the check.
- **Sharing sessions between nodes** (a session backend). Nodes are isolated by design. A moved session is a new
  session with its context carried, never the old one resumed.

## Follow-ups

- hugr-node: the federation client's reconnect, with its portable context replayed.
- quack: the state cookie on `/quack` responses once duckdb/duckdb-quack#297 is in.
- hugr-platform 002 (the front): no change is needed (label → node, gone → any node of the group); its check of a
  move joins the demo.
