# Authentication: the node verifies, a layer in front acquires

The one invariant everything else hangs off: **a node never runs an OAuth flow, never sees a
password, never mints a token.** It verifies an IdP-issued OIDC access token offline - JWKS
(`KEYS FROM '<url>'`, fetched through duckdb's own filesystem), RS256/ES256/HS256, issuer, audience,
`exp`/`nbf` - and resolves roles and claims into the ACL (specs 007/023). Keycloak and Entra tokens
verify the same way; a node may trust several issuers at once. (One Entra note, live-earned: Microsoft's JWKS endpoint needs `SET GLOBAL
force_download=true` under httpfs, and an app registration issues v1-style tokens unless its
`requestedAccessTokenVersion` is set to 2 - or simply configure the issuer as whatever `iss` the
token actually carries.)

## Token acquisition is the client side's

| client | who runs the flow | how |
| --- | --- | --- |
| DBeaver / JDBC tools | today: a pasted bearer (driver property `authorization` = `Bearer <jwt>`); planned: a custom Flight SQL driver with browser login (auth-code+PKCE) | [clients/dbeaver.md](clients/dbeaver.md) |
| ADBC (python) | the script supplies the header; in Azure/Fabric the environment's identity mints the token | [clients/adbc.md](clients/adbc.md) |
| duckdb + quack | a `TYPE quack` secret carries the token; planned: `PROVIDER oidc` runs the flow (token / client_credentials / device / password) at `CREATE SECRET` | [clients/quack.md](clients/quack.md) |
| Power BI | its connector runtime's native OAuth (planned connector) | [clients/powerbi-fabric.md](clients/powerbi-fabric.md) |

## The flow menu is the admin's policy

Which flows a deployment accepts is configuration, not doctrine: auth-code+PKCE (interactive GUI
default), device flow (terminals/CI), resource-owner password (only where the IdP allows it and the
org accepts it - off by default), raw bearer token (the escape hatch). One deployment may be
token-only, another password-only. Planned: the doors advertise their issuers and permitted flows on
an unauthenticated discovery surface so clients need no IdP configuration of their own.

## Session token binding (spec 059)

`acl_session_token_binding` decides when a token's `exp` is judged:

- **`connect` (default)** - freshness gates *establishment*. A session opened with a valid token
  keeps working until it goes idle (`acl_session_idle_timeout`, default 900s), is closed, or is
  killed (`acl_session_kill`). Nobody has to refresh a token mid-session - which no real client
  stack can do anyway - and short-lived IdP tokens stop breaking interactive work.
- **`every_use`** - the strict rule: `exp` is re-judged on every use, so disabling a user at the IdP
  ends their open session at the next statement. Choose it when revocation latency matters more than
  short-token ergonomics.

An expired token can never *open* a session under either setting - on the Flight door a stale
bearer continues its own established session (its signature and issuer still verify on every call;
only staleness is forgiven) and can never start a new one. Because idle is the only automatic
reaper under `connect`, disabling it (`acl_session_idle_timeout=0`) and `connect` refuse each
other at `SET`. The setting is GLOBAL-only and validated where set; an unrecognised value stored by
other means hardens to `every_use`, and a deployment without a policy catalog stays at `every_use`.
