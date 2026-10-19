# Deployment: one node

A node is a DuckDB instance with the acl extension loaded, a policy catalog, and one or both doors:

```sql
LOAD acl;
SELECT acl_use_db('store', 'acl', true);          -- the policy catalog
-- ... issuers, virtual catalog, roles, grants (see CLAUDE.md / specs) ...
SELECT acl_flight_serve('grpc://localhost:32700');            -- Arrow Flight SQL door
SELECT acl_flight_serve('grpc://0.0.0.0:32700', cert, key);   -- ... over TLS (spec 053)
SELECT acl_quack_serve('quack:localhost:31700', server_token); -- quack door (cleartext; proxy-terminate TLS)
```

- The Flight door speaks the protocol ADBC and JDBC drivers use; TLS is native (`grpc+tls`,
  cert/key inline-PEM or read through duckdb's filesystem). The one-arg form deliberately binds
  cleartext-localhost only.
- The quack door is quack's own server compiled into acl (spec 063): `acl_quack_serve(uri,
  token[, cert, key][, mode])` binds the public address itself, terminates TLS natively, and answers
  `GET /.well-known/quack-auth` - the issuers the node trusts, live from the policy - so clients can
  discover where to authenticate from the door address alone (503 `draining` while the node drains).
  `mode := 'plain'` is a bare cleartext server for a TLS-terminating proxy upstream. Details:
  [serving.md](serving.md).
- Sessions: each held session is a duckdb connection; `acl_max_sessions` (default 1000) bounds them,
  `acl_session_idle_timeout` (default 900s) reaps abandoned ones, `acl_sessions()` /
  `acl_session_kill(id)` are the ops surface.
- A ready-made demo node with seeded policy and tokens: `test/live/serve.sh [flight|quack|all]
  [--tls]` and the walk-through in `test/live/RUNBOOK.md`.

**The fleet** (many nodes behind a front that routes, reconciles configuration, and can terminate
authentication) is a separate product; nodes are identical either way, which is the point.

**Several nodes behind a front.** What a front must keep:

- **A session stays on one node while that node serves it.** Its connection, its transaction, its temp
  tables and its Flight tickets live on the node that opened it. When the node goes away, the session
  moves (below).
  - `GetFlightInfo` and its `DoGet` must reach the **same node**. A front that spreads one session
    over nodes breaks the ticket (`acl: unknown or already fetched ticket`).
  - A quack client opens several HTTP connections per logical connection, one per FETCH in flight,
    and all of them must reach the same node.
- **The node names its sessions** when `acl_node_label` is set. A front then routes by the name alone
  and keeps no table of sessions.
  - Both doors send the cookie `acl_node=<label>` to a client that does not carry it yet. A front
    routes every call carrying it to that node. The Flight session cookie, `acl_flight_session_id`,
    is unchanged.
  - The quack connection id the node mints starts with `<label>.`. Every request carries it in the
    message header at the start of its body. A quack client that keeps cookies per connection
    (duckdb/duckdb-quack#297) also sends the `acl_node` cookie and `X-Quack-Connection-Id`.
  - A Flight client that sends no cookies (ADBC's default) is kept on one node by its connection.
  - The label is a DNS label (`[a-z0-9-]`, at most 63 characters), GLOBAL only, set in the bootstrap
    before the doors serve, for example the pod's name. The load report shows it as `"label"`.
  - It is a routing hint and never an authority. A client that rewrites it only reaches another node,
    which verifies its token like any other and refuses a principal of another resource group.
- **DML is safest over `DoPut`.** It is one RPC, so there is no window between two calls. `JDBC
  executeUpdate`, prepared DML (announced as an update), `executemany` and `adbc_ingest` all take it.
- **A retried write may double** (spec 111). DML sent through the query path runs at `GetFlightInfo`.
  If the node dies, or the answer is lost, before the `DoGet`, the write may already be committed
  while the client sees an error.
  - Any DML RPC whose answer is lost after the commit is in the same position, `DoPut` included.
  - Writes a client may retry must be idempotent (MERGE, a key) or held in the client's own
    transaction (`BeginTransaction`), which the node rolls back with the session.
- **A session can move to another node** (spec 135) when its node goes away (a roll, a drain, a
  scale-down) or its session died there. The Flight door sets a third cookie, `acl_session_state`,
  holding the session's `USE` and the client-local settings the client `SET` (`TimeZone`, `Calendar`,
  `acl_metadata_max_rows`, the trace and lineage context), a tag of its principal, and whether something
  cannot move: an open transaction, a temp table, the view-as mode.
  - On a node that does not know the session, its context is restored before the call runs. Each item
    is judged again as if the client sent it now, so a `USE` of a catalog the principal no longer holds is
    refused. A long-lived read-only connection simply carries on.
  - Anything not carried refuses the call once and names all of it: `acl: the session moved to another
    node and lost its temp tables; the statement did not run, the connection works on`. The next call
    works on the new session, with whatever context did carry.
  - A lost transaction stays aborted on the new node until the client's `ROLLBACK` (or `EndTransaction`).
    Every statement in between is refused, and a `COMMIT` commits nothing. No part of it runs in
    autocommit.
  - A session that was in the view-as mode is not seated afresh, unless the call declares the mode
    (`x-acl-view-as`).
  - Another principal's token with the cookie carries nothing of it.
  - The move verifies the token again, as any new session does: a connection that has lived for months
    must present a valid token.
  - A front needs nothing for this. It routes by the label, and a label that is gone goes to any node of
    the group.
  - quack authenticates only at CONNECT, so a connection never moves by itself. A node that does not
    know a connection id answers `acl: this connection is not known on this node - connect again`.
- **Draining** (`acl_drain()`) keeps established sessions, unfetched tickets included, until they end
  or their idle timeout passes. The orchestrator owns the deadline.
