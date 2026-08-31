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
- The quack door is fronted (spec 062): `acl_quack_serve(uri, token[, cert, key])` serves TLS
  natively (the real quack listens loopback-only behind the front), and the front answers
  `GET /.well-known/quack-auth` - the issuers the node trusts, live from the policy - so clients
  can discover where to authenticate from the door address alone.
- Sessions: each held session is a duckdb connection; `acl_max_sessions` (default 1000) bounds them,
  `acl_session_idle_timeout` (default 900s) reaps abandoned ones, `acl_sessions()` /
  `acl_session_kill(id)` are the ops surface.
- A ready-made demo node with seeded policy and tokens: `test/live/serve.sh [flight|quack|all]
  [--tls]` and the walk-through in `test/live/RUNBOOK.md`.

**The fleet** (many nodes behind a front that routes, reconciles configuration, and can terminate
authentication) is a separate product; nodes are identical either way, which is the point.
