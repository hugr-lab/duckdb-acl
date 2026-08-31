# duckdb + quack

A duckdb process is the client; the attached catalog is the principal's virtual world.

```sql
LOAD httpfs; LOAD quack;
ATTACH 'quack:<host>:<port>' AS remote (TYPE quack, TOKEN '<access token>');
SELECT count(*) FROM remote.main.orders;               -- your slice
INSERT INTO remote.main.orders SELECT * FROM payload;  -- bulk SEND_DATA drain, enforced row by row
```

- Instead of an inline TOKEN, a secret works today: `CREATE SECRET s (TYPE quack, TOKEN '...',
  SCOPE 'quack:<host>:<port>')` and ATTACH without TOKEN.
- Bulk staging is a granted schema (spec 056): `CREATE TABLE remote.stage.load(...)`, drain into it,
  promote with ordinary SQL, `DROP` it. A bulk insert into a predicate-confined table needs the
  grant to carry a `COLUMNS` list (the drain is positional on the wire).
- The client's own `CREATE TEMP TABLE` is local to the client and never reaches the server.

## Planned (design/016 block A)

- `CREATE SECRET (TYPE quack, PROVIDER oidc, ISSUER ..., CLIENT_ID ..., FLOW
  'token'|'client_credentials'|'device'|'password' ...)` - the provider runs the flow at CREATE and
  re-mints on `CREATE OR REPLACE`; quack itself is unchanged.
- TLS and `/.well-known/quack-auth` discovery on the served side, fronted by the acl extension's own
  listener.
