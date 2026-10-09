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

- **A session stays on one node.** Its connection, its transaction, its temp tables and its Flight
  tickets live on the node that opened it.
  - `GetFlightInfo` and its `DoGet` must reach the **same node**: the front routes by the session
    cookie, `arrow_flight_session_id`. A front that spreads one session over nodes breaks the ticket
    (`acl: unknown or already fetched ticket`).
  - quack keeps its own connection id, so a quack client is sticky by construction.
- **DML is safest over `DoPut`.** It is one RPC, so there is no window between two calls. `JDBC
  executeUpdate`, prepared DML (announced as an update), `executemany` and `adbc_ingest` all take it.
- **A retried write may double** (spec 111). DML sent through the query path runs at `GetFlightInfo`.
  If the node dies, or the answer is lost, before the `DoGet`, the write may already be committed
  while the client sees an error.
  - Any DML RPC whose answer is lost after the commit is in the same position, `DoPut` included.
  - Writes a client may retry must be idempotent (MERGE, a key) or held in the client's own
    transaction (`BeginTransaction`), which the node rolls back with the session.
- **Draining** (`acl_drain()`) keeps established sessions, unfetched tickets included, until they end
  or their idle timeout passes. The orchestrator owns the deadline.
