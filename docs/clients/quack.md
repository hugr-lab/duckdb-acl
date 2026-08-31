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

## OIDC without hand-carried tokens (spec 061)

The `oidc` provider runs a real flow at `CREATE SECRET` and stores the minted token where quack
already looks - `ATTACH` then needs no TOKEN at all:

```sql
CREATE SECRET kc (TYPE quack, PROVIDER oidc, SCOPE 'quack:<host>:<port>',
                  ISSUER 'https://kc/realms/x', CLIENT_ID 'cli',
                  FLOW 'device');                      -- prints a URL + code, waits for approval
-- FLOW 'password'            + USERNAME/PASSWORD     (where the IdP allows it)
-- FLOW 'client_credentials'  + CLIENT_SECRET         (machine identity)
-- FLOW 'token'               + TOKEN                 (a token you already have)
ATTACH 'quack:<host>:<port>' AS remote (TYPE quack);   -- rides the secret
```

`CREATE OR REPLACE SECRET` re-mints - silently, off the cached refresh token, so a device flow does
not re-prompt. Passwords and client secrets are consumed by the flow and never stored; the secret
carries only the minted token (redacted) and the visible issuer/client/flow. `OAUTH_SCOPE` passes an
OAuth scope through (plain `SCOPE` is the secret's own matching clause).

## Planned (design/016 block A2)

- TLS and `/.well-known/quack-auth` discovery on the served side, fronted by the acl extension's own
  listener - after which `ISSUER` becomes optional (discovered from the door).
