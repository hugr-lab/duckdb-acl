# Authentication: how a principal is verified

The one invariant everything else hangs off: **a node never runs an OAuth flow for itself, never
stores a password, never mints a token.** It verifies an IdP-issued JWT offline - signature, issuer,
audience, `exp`/`nbf` - and resolves the token's roles and claims into the ACL (specs 007/023).
Acquisition is the client side's job (specs 060/061/064); the one place the node touches an IdP on a
client's behalf is the Flight door's password handshake, and even there the IdP's answer is verified
like any other bearer before it is trusted.

Keycloak and Entra tokens verify the same way; a node may trust several issuers at once. Two Entra
notes, live-earned (`test/live/RUNBOOK.md`): Microsoft's JWKS endpoint needs
`SET GLOBAL force_download=true` under httpfs, and an app registration issues v1-style tokens
(`iss: sts.windows.net/...`) unless its `requestedAccessTokenVersion` is set to 2 - or simply
configure the issuer as whatever `iss` the token actually carries.

## The three prefix forms

Every statement a node executes under the ACL starts with a prefix that names the principal. Who
writes it, and what the node checks, differs per form:

| prefix | who writes it | what the node verifies |
| --- | --- | --- |
| `ACL ROLE "r" <sql>` | a trusted gateway that has already authenticated the caller | nothing - the role name is taken as given; the principal is that one role plus the role's default claims |
| `ACL TOKEN '<jwt>' <sql>` | a gateway forwarding the caller's bearer | the JWT, offline, against the issuer registry (below); roles are the union of what the token maps to |
| `ACL SESSION '<handle>' <sql>` | a door (quack, Flight SQL) via `acl_session_sql` | that the handle is a live session; the stored principal is replayed verbatim |

`ACL ADMIN <mgmt>` is the fourth, anonymous form for the gateway's own administration; once a policy
source is enabled it needs `acl_allow_anonymous_admin=true`. A principal with the `manage` or
`passthrough` scope writes its administration after its own prefix instead (`ACL TOKEN '...' ACL
CREATE ROLE ...`). A client cannot smuggle a second prefix into its statement: a doubled prefix is
refused as an administration scope it does not hold.

A token that is not JWT-shaped falls to the dev stub `acl_define_token(token, role, claims_csv)`
(memory-only, never the catalog). A JWT-shaped token *always* takes the real path - it can fail, it
can never fall back to the stub.

## Issuers

An issuer is the node's trust anchor for one IdP: which keys sign its tokens, which audiences and
algorithms are acceptable, where the roles are, and which claims become `acl_claim('name')`.

```sql
ACL ADMIN CREATE ISSUER 'https://kc/realms/x'
    KEYS FROM 'https://kc/realms/x/protocol/openid-connect/certs'   -- or KEYS '<jwks or PEM>'
    AUDIENCES ('api://acl', 'account')          -- or AUDIENCES 'api://acl,account'
    ALGS (RS256)                                -- default RS256; the allowlist
    ROLE CLAIM 'realm_access.roles'             -- default 'roles'; a dot path
    CLAIM MAP (tid => tenant)                   -- or CLAIM MAP '{"tid": "tenant"}'
    CLIENT ID 'door-app' CLIENT SECRET '...';   -- spec 064, optional
```

The function form takes the same things positionally - four shapes, 6 to 9 arguments:

```sql
SELECT acl_define_issuer(issuer, keys_json, audiences_csv, algs_csv, role_claim, claim_map_json
                         [, jwks_uri [, client_id [, client_secret]]]);
```

- **Keys, one way or the other.** `keys_json` is a JWKS (`RSA` n/e, `EC` P-256 x/y, `oct` k) or a
  PEM public key; `jwks_uri` names a document to read instead. Exactly one of the two: both or
  neither is refused with *"an issuer carries its keys either as a document or as a location to read
  one from, and must state exactly one of them"*. `ALTER ISSUER ... SET KEYS '...'` clears the
  location and `SET KEYS FROM '...'` clears the paste - an issuer pointed at a document must not keep
  verifying against a paste nobody can see any more.
- **Audiences.** The token's `aud` (string or array) must intersect the list. A single `'*'` means
  the issuer deliberately accepts any audience. `ALTER ISSUER ... SET AUDIENCES` refuses an empty
  list (*"AUDIENCES must list at least one audience (use '*' to accept any)"*); note that an issuer
  *defined* with an empty list performs no audience check at all - state one.
- **Algorithms.** A closed allowlist: `RS256`, `ES256`, `HS256`. Anything else, `none` included, is
  refused with *"algorithm "X" is not allowed for this issuer"*. The key type follows the verified
  alg, so a token cannot pick a key of another kind.
- **Role claim.** A dot path into the payload (`roles`, `realm_access.roles`, `groups`); a string or
  an array of strings. Its values go through role mapping (below).
- **Claim map.** `{"<jwt dot path>": "<claim name>"}`. Each mapped value is read as text (strings,
  numbers and booleans all stringify) and becomes `acl_claim('<claim name>')` in RLS predicates and
  templates. A path absent from the token yields no claim - and an RLS predicate over a missing claim
  bakes `NULL`, which fails closed (spec 003).
- **Client id / secret** (spec 064): the OAuth client the node runs the Flight password handshake
  as, and what auth discovery advertises. A secret without an id is refused where written
  (*"a client_secret without a client_id authenticates nothing"*); clearing the id clears the
  secret with it.

`ALTER ISSUER '<iss>' SET KEYS | KEYS FROM | AUDIENCES | ALGS | ROLE CLAIM | CLAIM MAP | CLIENT ID |
CLIENT SECRET '<value>'` (function form `acl_alter_issuer(issuer, field, value)`, fields `keys |
jwks_uri | audiences | algs | role_claim | claim_map | client_id | client_secret`) changes an
existing issuer; `DROP ISSUER '<iss>'` / `acl_drop_issuer` removes it. `acl_issuers()` lists
`issuer, audiences, algs, role_claim, claim_map, jwks_uri, client_id` - never `keys_json` (an HS256
key is a shared secret) and never `client_secret`.

Issuers live in the policy catalog (`acl.issuers`) when one is enabled, in memory otherwise; an
enabled catalog is the exclusive source, like every other resolver.

### Keys read from a document (spec 023)

`KEYS FROM '<uri>'` reads the JWKS through duckdb's own filesystem (`read_text`), so an https URL
(needs httpfs, and httpfs says so itself) and a local file refreshed out of band are one mechanism.
Cached per instance, in memory:

| when | what happens |
| --- | --- |
| nothing cached, or the cache is older than `acl_jwks_refresh_interval` (300 s) | read |
| the token names a `kid` the cached document does not have | read, but no more often than every 10 seconds |
| the read fails and something is cached | keep using it until `acl_jwks_max_stale` (3600 s) has passed since the last *successful* read; `0` makes a failed read fatal at once |
| the read fails and nothing is cached | refuse: *"the keys of issuer "X" could not be read from "uri": <reason>"* |
| the issuer is repointed at another location | the cache does not apply; the new location is read at once |

Key selection inside a JWKS: a key whose `use` is not `sig` is skipped (a Keycloak realm publishes an
RSA-OAEP encryption key beside its signing key); a `kid` that matches nothing is *"no usable RS256
key for this issuer"*, never a fallback to another key. A token without a `kid` verifies only when
the JWKS holds exactly one signing key of the right type.

The memory store has no database handle and cannot read documents: without a policy catalog an
issuer with `KEYS FROM` refuses every token by name.

### Role mapping

Each value of the role claim becomes internal roles through the mappings:

```sql
ACL ADMIN MAP GROUP '9f3a0000-...' FROM ISSUER 'https://login.microsoftonline.com/<t>/v2.0' TO ROLE analyst;
ACL ADMIN MAP CLAIM 'ops' FROM ISSUER 'https://kc/realms/x' TO ROLE operator;
SELECT acl_map_role(issuer, source, external_value, role);   -- source: 'group' | 'claim-value'
ACL ADMIN DROP MAP GROUP|CLAIM '<value>' FROM ISSUER '...' TO ROLE r;   -- acl_drop_role_mapping
```

- One external value may map to several roles; a token carrying several values collects the union.
- An **unmapped** value is accepted as an internal role only if that role is actually known - a row
  in `roles`, or a role that holds a catalog grant; anything else is ignored.
- Zero resulting roles is a refusal: *"no recognized roles"*.
- The principal carries the whole role vector; grants resolve as the union across roles (spec 006).

**Entra ID**: app roles arrive in `roles` (the default role claim); security groups need
`ROLE CLAIM 'groups'` plus GUID mappings. When Entra replaces the groups claim by a Graph link
(**groups overage**, `_claim_names.groups`) the node refuses loudly - it is offline by design;
resolve groups at the gateway and use the ROLE form.

## What a token must carry, and how it is judged

The order of the checks, and what each refuses with (every message is prefixed
`acl_rewrite: token rejected: `):

1. **Shape** - three base64url segments, JSON header and payload, an `alg` in the header. Otherwise
   the token is not JWT-shaped and falls to the dev stub, which refuses it as unknown.
2. **Issuer** - the payload's `iss` must name a registered issuer: *"unknown issuer "X""*.
3. **Algorithm** - the header's `alg` must be in the issuer's allowlist.
4. **Key** - selected by the header's `kid` (and `use`), as above.
5. **Signature** - RSA-PKCS1v15/SHA-256, ECDSA P-256 over raw `r||s`, or HMAC-SHA256 in constant
   time: *"signature verification failed"*.
6. **`exp`** - mandatory (*"missing exp claim"*); refused once `exp + acl_jwt_clock_skew < now`:
   *"token expired"*. The skew is 60 s by default, GLOBAL.
7. **`nbf`** - optional; refused while `nbf - acl_jwt_clock_skew > now`: *"token not yet valid"*.
8. **`aud`** - must intersect the issuer's audiences unless they are `*`: *"audience not accepted"*.
9. **`sub`** - read as the subject; it goes into the Flight door's principal fingerprint so two users
   who share roles and claims are not one principal (spec 050).
10. **Roles** - the role claim's values, mapped; groups overage and zero roles refuse as above.
11. **Claims** - the claim map is applied; a claim map that is not a JSON object refuses.

No network IO exists on this path except the JWKS read behind its cache, so a pool of instances
stays deterministic.

## Role-default claims, and who wins

A role may carry default claims of its own:

```sql
ACL ADMIN CREATE ROLE analyst CLAIMS (tenant = 'acme');   -- or CLAIMS 'tenant=acme'
ACL ADMIN ALTER ROLE analyst SET CLAIMS (tenant = 'globex');
SELECT acl_define_role('analyst', 'tenant=acme');
```

They are what the bare `ROLE` form carries, and they are merged into a token principal for every
role the token maps to - **explicit token claims win** over a role default, so an IdP that states
`tid` overrides the role's `tenant` only if the claim map names it. The same merge runs when a
session is opened (spec 040's addendum): `ACL SESSION` answers exactly what `ACL TOKEN` would for
the same token, role defaults included.

## Sessions (spec 040) and token binding (spec 059)

A door turns a token into a principal **once** and attaches an opaque handle to every statement after
that, so the raw JWT never travels in query text, `EXPLAIN` output or logs.

```sql
acl_session_open(token)        -- 32 hex chars (128 random bits), or NULL if the token does not verify
acl_session_sql(handle, sql)   -- 'ACL SESSION ''<handle>'' ' || sql, or NULL if the session is not usable
acl_session_close(handle)      -- ends it; idempotent
acl_session_reason(handle)     -- 'live' | 'expired' | 'idle' | 'unknown' - read-only, survives the NULL
```

A door's whole job is "call `acl_session_sql`, run what it returns, refuse if it is NULL". All of
these are the door's, not a principal's: under a prefix each is refused (`... is not allowed`), so a
client can neither mint a session, compose a prefix, nor close somebody else's. A handle a client
invents is refused by the prefix itself: *"acl_rewrite: session unknown"* (or `expired` / `idle`).

**Sessions end when nobody ends them** (spec 044): a session dies after `acl_session_idle_timeout`
seconds unused (default 900; `0` disables the rule), `acl_session_sweep()` drops every dead record
and returns how many, `SessionOpen` runs the same pass itself at most once a minute or whenever the
map is at `acl_max_sessions` (default 1000; `0` unlimited). At the cap a new session is **refused**
(NULL), never an old one evicted. `acl_session_count()` reports the live total; `acl_sessions()`
returns a JSON array of `{"id", "subject", "roles", "idle_seconds", "expires_at"}` - a short public
id, never the handle - and `acl_session_kill(id)` ends one.

**Token binding** - `acl_session_token_binding` decides when a token's `exp` is judged:

- **`connect` (default)** - freshness gates *establishment*. A session opened with a valid token
  keeps working until it goes idle, is closed, or is killed. Nobody has to refresh a token
  mid-session - which no real client stack can do anyway - and short-lived IdP tokens stop breaking
  interactive work. `acl_sessions()` reports `expires_at` raw, so under `connect` a session may
  legitimately outlive it.
- **`every_use`** - `exp` is re-judged on every use, so disabling a user at the IdP ends their open
  session at the next statement. Choose it when revocation latency matters more than short-token
  ergonomics.

An expired token can never *open* a session under either setting. On the Flight door a stale bearer
continues its own established session (signature, issuer, audience, `nbf` and the roles still verify
on every call; only staleness is forgiven, and only for a live same-principal session) and can never
start a new one. Because idle is the only automatic reaper under `connect`, disabling it and
`connect` refuse each other at `SET`. The setting is GLOBAL-only and validated where set; an
unrecognised value stored by other means hardens to `every_use`. Without a policy catalog the store
cannot read the setting and stays at `every_use`.

## How clients get a token

The node advertises where to authenticate and verifies what comes back; the flow itself runs on the
client side or, for stock Flight drivers, through the door's IdP-gated handshake. Which flows work is
the IdP's policy, not a setting of ours - there is no flow toggle on the node.

| client | how a token arrives | details |
| --- | --- | --- |
| duckdb + quack | `CREATE SECRET (TYPE quack, PROVIDER oidc, ...)` runs the flow at CREATE and stores the minted token where quack reads it | [clients/quack.md](clients/quack.md) |
| Flight SQL, stock JDBC / ADBC | a pasted bearer in the `authorization` header, or Username/Password exchanged by the door (below) | [clients/dbeaver.md](clients/dbeaver.md), [clients/adbc.md](clients/adbc.md) |
| Fabric / Azure notebooks | the environment's identity mints an Entra token; passed as the same Bearer header | [clients/powerbi-fabric.md](clients/powerbi-fabric.md) |
| Power BI connector, browser-login JDBC driver, an `acl-login` agent | separate repos, not shipped here; the node is discoverable and password-capable for them | spec 064 |

### The quack provider secret (spec 061)

`CREATE SECRET s (TYPE quack, PROVIDER oidc, SCOPE 'quack:<host>:<port>', ISSUER '...',
CLIENT_ID '...', FLOW 'token' | 'client_credentials' | 'password' | 'device' [, CLIENT_SECRET ...]
[, USERNAME ...] [, PASSWORD ...] [, TOKEN ...] [, OAUTH_SCOPE ...])`. Every CREATE (OR REPLACE)
mints fresh; only the refresh token is cached, keyed by issuer, client, flow, username and scope.
`ISSUER` may be omitted when `SCOPE` names a concrete door - the door's
`GET /.well-known/quack-auth` answers the issuers it trusts, and the secret refuses by count when it
advertises none or several (*"name ISSUER explicitly"*). A missing FLOW is refused with guidance
(*"name a FLOW ('token', 'client_credentials', 'password' or 'device')"*); a flow missing its
credential with *"FLOW 'x' needs Y"*; an IdP refusal is surfaced verbatim (*"the password flow was
refused: ..."*).

### Discovery and the password handshake on the Flight door (spec 064)

The Handshake RPC answers two pre-auth questions unauthenticated:

- **Discovery**: a handshake payload of `discover-auth` returns the same document the quack door
  serves at `/.well-known/quack-auth`, composed live from the policy:

  ```json
  {"issuers":[{"issuer":"https://idp/","client_id":"door-app",
               "token_endpoint":"https://idp/token",
               "device_authorization_endpoint":"https://idp/device"}]}
  ```

  `client_id` appears when the issuer carries one; the endpoints come from the IdP's own OIDC
  discovery, cached process-wide (300 s, a failure 30 s) - an unreachable IdP leaves its issuer named
  and endpoint-less. Nothing private is in it, and the secret never is.

- **Password handshake**: `authorization: Basic <user:password>` on the Handshake becomes the OAuth
  password grant, run by the node against each issuer that carries a `CLIENT ID`, in listing order.
  The IdP's access token is verified offline exactly like any bearer and handed back in the response
  header `authorization: Bearer <token>` - where stock JDBC, ADBC and pyarrow's
  `authenticate_basic_token` read it. The password is used once, neither logged nor stored. Refusals
  are named: *"the password handshake needs a TLS door (acl_flight_serve with a certificate) -
  refused over cleartext"*, *"no issuer here carries a CLIENT ID, so the door cannot run the password
  grant - authenticate with a bearer token instead"*, *"OIDC discovery against X failed: ..."*, *"the
  IdP at X refused the password grant: ..."* (an IdP with ROPC off answers
  `unsupported_grant_type`), *"the token the IdP at X answered does not verify against this door's
  issuers"*, and *"node is draining - not accepting new sessions"* (spec 066).

A payload-less, header-less handshake still succeeds and gates nothing (spec 058): the per-call
Bearer header remains the real gate.

## Settings

All GLOBAL (`SET GLOBAL ...`); the store reads them through the instance, so a session-scoped `SET`
would report success and change nothing. Without a policy catalog the defaults apply and cannot be
changed.

| setting | default | meaning |
| --- | --- | --- |
| `acl_jwt_clock_skew` | 60 | seconds of skew allowed on `exp`/`nbf` |
| `acl_jwks_refresh_interval` | 300 | seconds a fetched JWKS is used before it is read again |
| `acl_jwks_max_stale` | 3600 | seconds a JWKS that can no longer be read may still be used; `0` = a failed read is fatal |
| `acl_session_idle_timeout` | 900 | seconds a session may go unused; `0` disables (refused under `connect`) |
| `acl_session_token_binding` | `connect` | when `exp` is judged: `connect` or `every_use` |
| `acl_max_sessions` | 1000 | live sessions at once; a new one is refused at the cap; `0` unlimited |
| `acl_allow_anonymous_admin` | false | whether a bare `ACL ADMIN` is accepted once a policy source is enabled |

## Troubleshooting: verification refusals

| message | meaning | what to do |
| --- | --- | --- |
| `token rejected: unknown issuer "X"` | the payload's `iss` matches no registered issuer | define the issuer exactly as `iss` is spelled (Entra: v1 vs v2 issuer strings) |
| `token rejected: not a JWT` / `malformed JWT JSON` | the value is not three base64url JSON segments | check what the client sends; a non-JWT string is only for the dev stub |
| `token rejected: algorithm "X" is not allowed for this issuer` | `alg` not in the allowlist | add it with `ALTER ISSUER ... SET ALGS` if the IdP really signs with it |
| `token rejected: unsupported algorithm "X"` | allowlisted but not implemented | only RS256, ES256, HS256 exist |
| `token rejected: no usable RS256|ES256|HS256 key for this issuer` | no signing key of that type, or the `kid` matches nothing (mid-rotation) | check the JWKS carries a `use: sig` key with that `kid`; a fresh read happens on an unknown `kid` at most every 10 s |
| `token rejected: malformed RSA|EC|oct JWK` / `malformed ES256 signature` | the key or signature bytes do not decode | the pasted JWKS is broken, or the token is not what its header says |
| `token rejected: signature verification failed` | the key was found and the signature does not match | rotated key, wrong issuer secret, or a tampered payload |
| `token rejected: missing exp claim` | `exp` is mandatory | the IdP must issue one |
| `token rejected: token expired` | `exp + skew < now` | fetch a fresh token; check the clocks; a live session under `connect` is unaffected |
| `token rejected: token not yet valid` | `nbf - skew > now` | the clocks disagree by more than `acl_jwt_clock_skew` |
| `token rejected: audience not accepted` | `aud` intersects nothing | add the audience, or `'*'` if the issuer deliberately accepts any |
| `token rejected: groups overage - the groups claim was replaced by a Graph link; resolve groups at the gateway and use the ROLE form` | Entra put too many groups to inline | use app roles, or resolve groups upstream |
| `token rejected: no recognized roles` | every role value was unmapped and unknown | `MAP GROUP|CLAIM`, or create/grant the role the token names |
| `token rejected: issuer claim_map is not a JSON object` | the stored claim map is malformed | `ALTER ISSUER ... SET CLAIM MAP` |
| `token rejected: the keys of issuer "X" could not be read from "uri": ...` | nothing cached and the read failed | the reason is duckdb's own (httpfs missing, 404, ...) |
| `token rejected: the keys of issuer "X" were last read N seconds ago and "uri" is still unreadable (...); acl_jwks_max_stale is M` | the cached keys are older than allowed | fix the location; raise `acl_jwks_max_stale` only knowingly |
| `token rejected: issuer "X" reads its keys from "uri", which needs a policy catalog - the in-memory store cannot read documents` | `KEYS FROM` without `acl_use_db` | enable a policy catalog, or paste the keys |
| `session unknown` / `session expired` / `session idle` | the `ACL SESSION` handle is not usable | the door reconnects; `acl_session_reason` tells the client why |
| `... requires a quoted value` | `ACL SESSION`/`TOKEN` without a quoted value | a door composes the prefix; a client never writes one |
| `acl_session_token_binding accepts 'connect' or 'every_use', not 'X'` / `... is global - use SET GLOBAL` | a bad or session-scoped value | `SET GLOBAL` one of the two |
| `acl_session_idle_timeout=0 would leave no automatic session reaper under acl_session_token_binding='connect' ...` / `... needs a live idle reaper ...` | the reaper-less combination | switch the binding to `every_use` first, or keep idle > 0 |
| `acl_define_issuer: an issuer carries its keys either as a document or as a location ...` | both or neither of keys / `KEYS FROM` | state exactly one |
| `... a client_secret without a client_id authenticates nothing` / `a CLIENT SECRET without a CLIENT ID ...` | secret without id | set the `CLIENT ID` first |

## Not verified

- Whether an *empty* `algs` argument to `acl_define_issuer` (as opposed to an omitted one) falls back
  to `RS256` or leaves the allowlist empty; the SQL form always defaults to `RS256`.
- The exact text of the "requires a quoted value" and "is not allowed" refusals beyond the fragments
  the tests pin.
