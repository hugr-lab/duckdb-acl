# Authentication: how a principal is verified

The one invariant everything else hangs off: **a node never runs an OAuth flow for itself, never
stores a password, never mints a token.** It verifies an IdP-issued JWT offline - signature, issuer,
audience, `exp`/`nbf` - and routes it to the one client of its issuer that accepts it, which makes
roles and attributes of it (specs 007, 023, 095).
Acquisition is the client side's job (specs 060/061/064); the one place the node touches an IdP on a
client's behalf is the Flight door's password handshake, and even there the IdP's answer is verified
like any other bearer before it is trusted.

Keycloak and Entra tokens verify the same way; a node may trust several issuers at once. Two Entra
notes, live-earned (`test/live/RUNBOOK.md`): Microsoft's discovery and JWKS endpoints need
`SET GLOBAL force_download=true` under httpfs, and an app registration issues v1-style tokens
(`iss: sts.windows.net/...`) unless its `requestedAccessTokenVersion` is set to 2 - or simply
configure the issuer as whatever `iss` the token actually carries.

## The three prefix forms

Every statement a node executes under the ACL starts with a prefix that names the principal. Who
writes it, and what the node checks, differs per form:

| prefix | who writes it | what the node verifies |
| --- | --- | --- |
| `ACL ROLE "r" <sql>` | a trusted gateway that has already authenticated the caller | nothing - the role name is taken as given; the principal is that one role plus the role's default claims |
| `ACL TOKEN '<jwt>' <sql>` | a gateway forwarding the caller's bearer | the JWT, offline, against its issuer and the one client that accepts it (below); roles are the union of what that client makes of it |
| `ACL SESSION '<handle>' <sql>` | a door (quack, Flight SQL) via `acl_session_sql` | that the handle is a live session; the stored principal is replayed verbatim |

`ACL ADMIN <mgmt>` is the fourth, anonymous form for the gateway's own administration; once a policy
source is enabled it needs `acl_allow_anonymous_admin=true`. A principal with the `manage` or
`passthrough` scope writes its administration after its own prefix instead (`ACL TOKEN '...' ACL
CREATE ROLE ...`). A client cannot smuggle a second prefix into its statement: a doubled prefix is
refused as an administration scope it does not hold.

A token that is not JWT-shaped falls to the dev stub `acl_define_token(token, role, claims_csv)`
(memory-only, never the catalog). A JWT-shaped token *always* takes the real path - it can fail, it
can never fall back to the stub.

## Issuers and clients (spec 095)

A token becomes a principal in three steps, each an object of its own:

1. **`ISSUER`** - the trust anchor for one IdP: its URL (the token's `iss`) and where its keys come
   from - the IdP's OIDC discovery by default.
2. **`CLIENT`** - which tokens of that issuer count and how to read them: the audiences it accepts,
   optionally the authorized party (`azp`) and conditions on claims; where the role values are, the
   attributes RLS reads (`acl_claim('name')`), the subject; and, for drivers, a client id and flows.
3. **Role mappings**, scoped to a client or an issuer: raw values become roles. Grants go to roles
   only - who the user is matters to the audit, never to a grant.

**No key and no credential is ever written into the policy.** A client secret, pasted keys and
algorithm overrides live in a secret of the node's secrets service (a catalog of type `tresor`, the
same one as spec 082) and are named by it; the policy keeps the secret's name. Writing
`KEYS`, `ALGS` or `CLIENT SECRET` into `CREATE ISSUER` is refused and says where they go.

### The short form: one IdP, one application

```sql
ACL ADMIN CREATE ISSUER 'https://kc/realms/x'
    AUDIENCES ('account')                       -- required: the token's aud must be one of them
    ROLE CLAIM 'realm_access.roles'             -- where the role values are (default 'roles')
    CLAIM MAP (tid => tenant)                   -- jwt path => acl_claim name
    CLIENT ID 'acl-desktop';                    -- optional: what drivers log in as
```

A quoted URL in place of a name is the short form. It creates the issuer, named by its URL, and its
**implicit client** of the same name: the audiences, the role claim, the claim map, the client id -
and, because a single own IdP usually names its roles like the ACL does, an unmapped role value that
names an existing role is that role (`UNMAPPED AS ROLE`). With a public client id its flows default
to the drivers' `authcode, device`; a client whose secret carries a `CLIENT_SECRET` (below) defaults
to `password`; the door's password flow is otherwise only ever written (`FLOWS (password, …)`).
Defaults apply when the client is created - a later `ALTER` never brings them back.
`ALTER ISSUER '<url>' SET …` changes the issuer and its implicit client; `DROP ISSUER '<url>'` and
`CREATE OR REPLACE ISSUER` remove its implicit client and every mapping scoped to the issuer or to
it (a replace may point the name at another IdP, where the old values mean nothing).

### Keys and algorithms: discovery by default

The node reads `<url>/.well-known/openid-configuration`, checks that the document names exactly this
issuer, and reads the JWKS its `jwks_uri` names - both through duckdb's own filesystem
(`read_text`), so an https IdP needs httpfs (and httpfs says so itself). The algorithms are the
document's `id_token_signing_alg_values_supported` that this node verifies (RS256, ES256), or RS256
when the document lists none. An IdP that signs only with something else is refused by name.

An `oidc_issuer` secret overrides that, for an IdP whose discovery is not reachable from the node
(an internal hostname, a pinned key) or for a shared key:

```sql
CREATE PERSISTENT SECRET kc_conn IN corp (TYPE oidc_issuer,
    URL 'https://kc/realms/x',                  -- optional: the URL may live here instead
    KEYS_FROM 'https://kc.internal/realms/x/protocol/openid-connect/certs',  -- or KEYS '<jwks>'
    ALGS 'RS256');                              -- optional
ACL ADMIN CREATE ISSUER kc FROM SECRET kc_conn [IN corp];
```

- **HS256** only from pasted `KEYS` in a secret whose `ALGS` names it: a key fetched from a location
  is never a shared secret.
- **One home per parameter**: the URL is on the issuer or in its secret, never both (refused where
  written, and fail closed where used if the secret later says otherwise).
- **Read at use**: the secret is read when a token is judged, through the service's own cache - a
  rotated key takes effect with no policy write. A change of the *connection* (URL, key source,
  algorithms, a pasted key - whoever holds a swapped-in key mints the issuer's tokens; for a client
  its audiences and client id) is a `policy` event `connection_changed` naming the object, with a
  fingerprint and never a value, where the node next resolves it (a change made while a node was
  down shows as none on it); a rotated `CLIENT_SECRET` is not.
- A secret is attached **by name only** - `FROM SECRET s`, with `IN <service>` when several are
  attached - and only from a secrets service: a secret of that name in the node's own memory or
  `local_file` storage is never read.

**Caching and the rotation verbs** (spec 023, now per location): the discovery document and the
JWKS are cached by location.

| when | what happens |
| --- | --- |
| nothing cached, or older than `acl_jwks_refresh_interval` (300 s) | read |
| the token names a `kid` the cached JWKS does not have | read, but no more often than every 10 seconds |
| the read fails and something is cached | keep using it until `acl_jwks_max_stale` (3600 s) has passed since the last *successful* read; `0` makes a failed read fatal at once |
| the read fails and nothing is cached | refuse: *"issuer "X" could not read "location": <reason>"* |

**Where a node reads from** (spec 071): `acl_jwks_locations` (GLOBAL, default `https://`) lists,
comma-separated, the prefixes every location the node reads may start with - the discovery document,
the JWKS it names, a secret's `KEYS_FROM`. `'https://, /etc/acl/jwks/'` admits any https URL and the
files under that directory, `'https://kc.corp/realms/'` pins one origin, `''` admits nothing. A
location outside the list is refused where it would be read, against the setting as it is on *this*
node, now: the token is rejected (*"issuer "X" reads "location", which this node does not: …"*),
a cached document is not used either, the refusal is the row's error in `acl_jwks_cache()`, and a
`keys` event `location_refused` (reason `policy_error`) carries it - a policy catalog shared by a
fleet, or a secret, cannot make one node read what it was not told to. Prefixes are compared as
written (a host prefix ends in `/`, or `https://kc.corp` also admits `https://kc.corp.evil/`); a
location containing `..` is refused whatever the list says. The setting is global only.

`acl_jwks_cache()` answers one row per cached location - `issuer` (the one that read it last),
`location`, `allowed`, `fetched_at` / `age_seconds`, `last_tried_at`, `error`, `keys` and `kids`
(the public names, never the keys). `acl_jwks_refresh([issuer])` drops what one issuer (or every
issuer) read, so the next token reads again - the rotation-incident verb. Both are the operator's.

Key selection inside a JWKS: a key whose `use` is not `sig` is skipped; a `kid` that matches nothing
is *"no usable RS256 key for this issuer"*, never a fallback to another key.

### Clients: several applications of one IdP

```sql
ACL ADMIN CREATE ISSUER kc URL 'https://kc/realms/x';

ACL ADMIN CREATE CLIENT desktop ISSUER kc
    AUDIENCES ('account') AZP ('acl-desktop')
    ROLES FROM ('realm_access.roles', 'groups')
    ATTRIBUTES (tenant = 'tenant', mail = ('upn', 'email'))
    SUBJECT ('email', 'sub')
    CLIENT ID 'acl-desktop' FLOWS (authcode, device);

ACL ADMIN CREATE CLIENT door ISSUER kc AUDIENCES ('account') AZP ('acl-door')
    ROLES FROM ('realm_access.roles') FLOWS (password) FROM SECRET kc_door;  -- CLIENT_SECRET there

ACL ADMIN CREATE CLIENT etl ISSUER github AUDIENCES ('acl-node')
    REQUIRE (sub LIKE 'repo:hugr-lab/etl:%', repository_owner = 'hugr-lab')
    ROLES CONSTANT ('etl_writer') ATTRIBUTES (pipeline = CONSTANT 'etl');
```

| clause | meaning |
| --- | --- |
| `AUDIENCES (…)` | **required** (here or in the client's secret); the token's `aud` must intersect |
| `AZP (…)` | the token's `azp` must be one of them (an Entra v1 token, `ver` 1.0, names it `appid`) |
| `REQUIRE (…)` | all must hold: `path = 'v'` (or a bare `true` / number), `path IN ('a', …)`, `'v' IN path` (an array claim contains it), `path LIKE 'p%'` - SQL's `LIKE`: `_` is any one character too, there is no escape |
| `ROLES FROM (…)` | claim paths whose values are role candidates (the union; a string or an array each) |
| `ROLES CONSTANT (…)` | roles every token of the client gets |
| `UNMAPPED IGNORE` / `UNMAPPED AS ROLE` | what an unmapped candidate does; an explicit client defaults to `IGNORE` |
| `ATTRIBUTES (…)` | `name = 'path'`, `= ('path', 'fallback', …)` or `= CONSTANT 'v'` - read as `acl_claim('name')` |
| `SUBJECT 'path'` / `('path', …)` | the subject (default `sub`): never a grant's, but the user's identity to the audit and to a secrets service that acts for sessions (`<issuer URL>|<subject>`) - keep it a claim the IdP owns |
| `TOKEN TYPE 'at+jwt'` | refuse a token of another `typ` (RFC 9068: no ID token as an access token) |
| `CLIENT ID '…'` | the OAuth client a driver or the door runs a flow as |
| `FLOWS (…)` | `password` (the door's handshake), `authcode`, `device` (drivers), `client_credentials` |
| `FROM SECRET s [IN c]` | an `oidc_client` secret: `AUDIENCES`, `CLIENT_ID`, `CLIENT_SECRET` |

A claim path is first looked up as one key (Entra's URL-shaped claim names), then walked as a dot
path - so a top-level claim spelled `a.b` wins over a nested `a` → `b`. A bare object name is a word
(letters, digits, `_`); quote a name with `-` or `.` in it. A client without `FLOWS` only accepts tokens - an external application or a CI job.
`ALTER CLIENT c SET <clauses>` / `DROP FROM SECRET` change it; `DROP CLIENT c` removes it with its
mappings; an issuer with explicit clients is dropped only after them.

**Routing: exactly one client per token.** The token's `iss` names the issuer; among that issuer's
clients the candidates are those whose audiences, `AZP` and `REQUIRE` accept it; the most specific
wins - a client with `AZP` or `REQUIRE` over an explicit one without, over the implicit client of the
short form. Two candidates of equal specificity are **refused as ambiguous**, never unioned; two
clients that would accept the same tokens are refused already where they are written (overlapping
audiences and `AZP`, neither with `REQUIRE`). No candidate is *"no client of issuer "X" accepts this
token (<why>)"*.

### Roles

1. The candidates are the values at every `ROLES FROM` path.
2. Each is looked up in the client's own mappings and its issuer's; it becomes every role it maps to.
3. An unmapped one is dropped (`UNMAPPED IGNORE`) or kept as the role of the same name if that role
   exists (`UNMAPPED AS ROLE`).
4. `ROLES CONSTANT` are added. An empty result is *"no recognized roles"*.

```sql
ACL ADMIN MAP GROUP '9f3a0000-...' FROM CLIENT desktop TO ROLE finance;   -- an identifier (Entra group)
ACL ADMIN MAP CLAIM 'sales' FROM ISSUER kc TO ROLE analyst;               -- for every client of kc
ACL ADMIN DROP MAP CLAIM 'sales' FROM ISSUER kc TO ROLE analyst;
SELECT acl_map_role('client' | 'issuer', scope, 'group' | 'claim-value', external_value, role);
```

**A role that administers** - one that holds `manage` or `passthrough` (spec 009), globally or on a
catalog - is reached **only through an explicit mapping of the client itself**: an issuer-scope
mapping to it is refused where written and dropped where used, `UNMAPPED AS ROLE` never yields it,
`ROLES CONSTANT` cannot name it, and a role that becomes privileged later is dropped at use. So a
customer's IdP can never hand out administration by naming a group `admin`.

**Attributes** are what RLS reads. A `CONSTANT` attribute is the ceiling a token cannot pass - the
pattern for several customers on one node: each customer's IdP is an issuer (or a broker's client
per customer, told apart by `REQUIRE`), its clients `UNMAPPED IGNORE`, its roles only through its
client's mappings, and an `org = CONSTANT 'acme'` attribute in the RLS. There is no tenant object.

**Entra ID**: app roles arrive in `roles`; security groups need `ROLES FROM ('groups')` plus GUID
mappings. When Entra replaces the groups claim by a Graph link (**groups overage**,
`_claim_names.groups`) and no role results, the node refuses loudly - it is offline by design;
resolve groups at the gateway and use the ROLE form.

### The function forms and the listings

```sql
SELECT acl_define_issuer(name, '{"url": …, "secret": …, "service": …, "client": {<client spec>}}' [, mode]);
SELECT acl_alter_issuer(name, '<issuer spec>');   SELECT acl_drop_issuer(name [, mode]);
SELECT acl_define_client(name, issuer, '<client spec>' [, mode]);
SELECT acl_alter_client(name, '<client spec>');   SELECT acl_drop_client(name [, mode]);
```

A client spec is the JSON the SQL forms compile to: `audiences`, `azp`, `require`
(`[{"path", "op": "eq|in|contains|like", "values"}]`), `roles_from`, `roles_constant`,
`unmapped` (`ignore|as_role`), `attributes` (`[{"name", "paths"|"constant"}]`), `subject`,
`token_type`, `client_id`, `flows`, `secret`, `service`; a JSON `null` clears a field. `mode` is
`create` (refuse an existing one), `replace` (the function default) or `skip`.

`acl_issuers()` (`name, url, secret_service, secret`), `acl_clients()` and `acl_role_mappings()`
list what is stored - a value kept in a secret is NULL there, beside the secret's name; nothing in
them is a key or a credential. The memory store keeps the same model and reads discovery, documents
and secrets through its instance like a catalog does; a function-driver source serves the three as
the optional slots `issuers`, `clients` and `role_mappings` (no arguments, the tables' columns in
order).

## What a token must carry, and how it is judged

The order of the checks, and what each refuses with (every message is prefixed
`acl_rewrite: token rejected: `):

1. **Shape** - three base64url segments, JSON header and payload, an `alg` in the header. Otherwise
   the token is not JWT-shaped and falls to the dev stub, which refuses it as unknown.
2. **Issuer** - the payload's `iss` must be the URL of exactly one issuer: *"unknown issuer "X""*
   (with the issuers whose URL is in a secret that could not be read named, when there are any).
3. **Algorithm** - the header's `alg` must be one the issuer allows (above).
4. **Key** - from the discovery's JWKS, a secret's `KEYS_FROM`, or a secret's `KEYS`; selected by
   `kid` and `use`.
5. **Signature** - RSA-PKCS1v15/SHA-256, ECDSA P-256 over raw `r||s`, or HMAC-SHA256 in constant
   time: *"signature verification failed"*.
6. **`exp`** - mandatory (*"missing exp claim"*); refused once `exp + acl_jwt_clock_skew < now`:
   *"token expired"*. The skew is 60 s by default, GLOBAL.
7. **`nbf`** - optional; refused while `nbf - acl_jwt_clock_skew > now`: *"token not yet valid"*.
8. **Client** - exactly one client of the issuer accepts it (audiences, `AZP`, `REQUIRE`,
   `TOKEN TYPE`), as above.
9. **Subject** - the client's subject paths; it goes into the Flight door's principal fingerprint so
   two users who share roles and claims are not one principal (spec 050).
10. **Roles** - the client's roles; groups overage and zero roles refuse as above.
11. **Attributes** - the client's attributes become the principal's claims.

No network IO exists on this path except the document reads behind their cache (and the secrets
service's own, behind its), so a pool of instances stays deterministic.

## Role-default claims, and who wins

A role may carry default claims of its own:

```sql
ACL ADMIN CREATE ROLE analyst CLAIMS (tenant = 'acme');   -- or CLAIMS 'tenant=acme'
ACL ADMIN ALTER ROLE analyst SET CLAIMS (tenant = 'globex');
SELECT acl_define_role('analyst', 'tenant=acme');
```

They are what the bare `ROLE` form carries, and they are merged into a token principal for every
role the token maps to - **explicit token claims win** over a role default, so an IdP that states
`tid` overrides the role's `tenant` only if the client's attributes name it. The same merge runs when a
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
  {"issuers":[{"name":"kc","issuer":"https://idp/realms/x",
               "token_endpoint":"https://idp/token",
               "device_authorization_endpoint":"https://idp/device",
               "authorization_endpoint":"https://idp/auth",
               "clients":[{"name":"desktop","client_id":"acl-desktop","flows":["authcode","device"]}]}]}
  ```

  Every issuer the node can resolve now is named; its clients are listed when they carry a client id
  and a driver flow (`authcode`, `device`) - a client id is public even when it is kept in a secret;
  a client secret is never read for it. The document is cached for 10 s within one policy version
  (the callers are unauthenticated); the endpoints come from the IdP's own OIDC discovery, cached
  process-wide (300 s, a failure 30 s) - an unreachable IdP leaves its issuer named and
  endpoint-less, and an issuer whose URL is in a secret that cannot be read now is left out.

- **Password handshake**: `authorization: Basic <user:password>` on the Handshake becomes the OAuth
  password grant, run by the node as **the one** client of the node with the `password` flow - its
  `CLIENT_SECRET`, when it has one, read from the secrets service for this call only. A user's
  password goes to exactly one IdP: with several password clients the handshake is refused rather
  than tried at one IdP after another (which would hand one customer's passwords to another's token
  endpoint), and the token endpoint must be on `acl_jwks_locations` too.
  The IdP's access token is verified offline exactly like any bearer and handed back in the response
  header `authorization: Bearer <token>` - where stock JDBC, ADBC and pyarrow's
  `authenticate_basic_token` read it. The base64 may come with or without its `=` padding (spec 089:
  arrow-go, under ADBC's Go and Python drivers, sends none). The password is used once, neither logged nor stored. Refusals
  are named: *"the password handshake needs a TLS door (acl_flight_serve with a certificate) -
  refused over cleartext"*, *"no client here runs the password flow (FLOWS (password)), so the door cannot
  run the password grant - authenticate with a bearer token instead"*, *"several clients run the
  password flow (a, b), so the door cannot tell whose IdP the password is for - …"*, *"the token
  endpoint of X is not a location this node reads: …"*, *"OIDC discovery against X failed: ..."*, *"the
  IdP at X refused the password grant: ..."* (an IdP with ROPC off answers
  `unsupported_grant_type`), *"the token the IdP at X answered does not verify against this door's
  issuers"*, and *"node is draining - not accepting new sessions"* (spec 066).

A payload-less, header-less handshake still succeeds and gates nothing (spec 058): the per-call
Bearer header remains the real gate.

## Settings

All GLOBAL (`SET GLOBAL ...`); the store reads them through the instance, so a session-scoped `SET`
would report success and change nothing. The memory store reads the `acl_jwt_*` / `acl_jwks_*`
settings too (spec 095); the session settings need a policy catalog.

| setting | default | meaning |
| --- | --- | --- |
| `acl_jwt_clock_skew` | 60 | seconds of skew allowed on `exp`/`nbf` |
| `acl_jwks_refresh_interval` | 300 | seconds a read document (discovery, JWKS) is used before it is read again |
| `acl_jwks_max_stale` | 3600 | seconds a document that can no longer be read may still be used; `0` = a failed read is fatal |
| `acl_jwks_locations` | `https://` | comma-separated prefixes every location the node reads keys from may start with (discovery, JWKS, a secret's `KEYS_FROM`); `''` admits none (specs 071, 095) |
| `acl_session_idle_timeout` | 900 | seconds a session may go unused; `0` disables (refused under `connect`) |
| `acl_session_token_binding` | `connect` | when `exp` is judged: `connect` or `every_use` |
| `acl_max_sessions` | 1000 | live sessions at once; a new one is refused at the cap; `0` unlimited |
| `acl_allow_anonymous_admin` | false | whether a bare `ACL ADMIN` is accepted once a policy source is enabled |

## Troubleshooting: verification refusals

| message | meaning | what to do |
| --- | --- | --- |
| `token rejected: unknown issuer "X"` | the payload's `iss` is no issuer's URL | define the issuer exactly as `iss` is spelled (Entra: v1 vs v2 issuer strings); "(the URL of … is in a secret that could not be read)" names issuers whose secret was unreadable |
| `token rejected: not a JWT` / `malformed JWT JSON` | the value is not three base64url JSON segments | check what the client sends; a non-JWT string is only for the dev stub |
| `token rejected: algorithm "X" is not allowed for this issuer` | `alg` is not one the issuer allows | an IdP's discovery lists what it signs with; HS256 needs pasted `KEYS` and `ALGS 'HS256'` in a secret |
| `token rejected: issuer "X" signs with A, B - this node verifies RS256 and ES256` | the discovery lists only algorithms this node does not verify from a location | configure the IdP to sign with RS256/ES256, or paste a key into a secret |
| `token rejected: the discovery document of issuer "X" names issuer "Y", not "X"` / `… names no jwks_uri` | the document is somebody else's, or has no keys | check the URL (a trailing slash is part of it); `KEYS_FROM` in a secret for an IdP without discovery |
| `token rejected: unsupported algorithm "X"` | allowlisted but not implemented | only RS256, ES256, HS256 exist |
| `token rejected: no usable RS256|ES256|HS256 key for this issuer` | no signing key of that type, or the `kid` matches nothing (mid-rotation) | check the JWKS carries a `use: sig` key with that `kid`; a fresh read happens on an unknown `kid` at most every 10 s |
| `token rejected: malformed RSA|EC|oct JWK` / `malformed ES256 signature` | the key or signature bytes do not decode | the pasted JWKS is broken, or the token is not what its header says |
| `token rejected: signature verification failed` | the key was found and the signature does not match | rotated key, wrong issuer secret, or a tampered payload |
| `token rejected: missing exp claim` | `exp` is mandatory | the IdP must issue one |
| `token rejected: token expired` | `exp + skew < now` | fetch a fresh token; check the clocks; a live session under `connect` is unaffected |
| `token rejected: token not yet valid` | `nbf - skew > now` | the clocks disagree by more than `acl_jwt_clock_skew` |
| `token rejected: no client of issuer "X" accepts this token (audience not accepted)` | `aud` intersects no client's audiences | add the audience to the client the token is for |
| `token rejected: no client of issuer "X" accepts this token (<why>)` | `azp`, a `REQUIRE` condition or `TOKEN TYPE` did not hold for any client | the reason is the first client the token was meant for (past its audience) |
| `token rejected: the token fits clients a, b of issuer "X" equally` | two clients of equal specificity accept it | tell them apart by `AUDIENCES`, `AZP` or `REQUIRE` |
| `token rejected: groups overage - the groups claim was replaced by a Graph link; resolve groups at the gateway and use the ROLE form` | Entra put too many groups to inline | use app roles, or resolve groups upstream |
| `token rejected: no recognized roles` | no role value was mapped (or kept by `UNMAPPED AS ROLE`), no constant, or only a privileged role reached other than through the client's own mapping | `MAP … FROM CLIENT`, or create/grant the role the token names |
| `token rejected: issuer "X" could not read "location": ...` | nothing cached and the read failed | the reason is duckdb's own (httpfs missing, 404, ...) |
| `token rejected: issuer "X" last read "location" N seconds ago and it is still unreadable (...); acl_jwks_max_stale is M` | the cached document is older than allowed | fix the location; raise `acl_jwks_max_stale` only knowingly |
| `token rejected: issuer "X" reads "location", which this node does not: … is outside acl_jwks_locations (…)` | the location is not on this node's list (spec 071) | list its prefix in `acl_jwks_locations` |
| `token rejected: the secret of issuer|client "X" (service.name) cannot be read` | the secrets service is down, detached, or the node may not `use` the secret | the service's own audit says why |
| `token rejected: client "X" has a parameter both on itself and in its secret` | the secret gained a field the client also states (judged at use, fail closed) | keep it in one place |
| `session unknown` / `session expired` / `session idle` | the `ACL SESSION` handle is not usable | the door reconnects; `acl_session_reason` tells the client why |
| `... requires a quoted value` | `ACL SESSION`/`TOKEN` without a quoted value | a door composes the prefix; a client never writes one |
| `acl_session_token_binding accepts 'connect' or 'every_use', not 'X'` / `... is global - use SET GLOBAL` | a bad or session-scoped value | `SET GLOBAL` one of the two |
| `acl_session_idle_timeout=0 would leave no automatic session reaper under acl_session_token_binding='connect' ...` / `... needs a live idle reaper ...` | the reaper-less combination | switch the binding to `every_use` first, or keep idle > 0 |
| `acl admin: an issuer's keys and algorithms are never written into the policy …` / `a client secret is never written into the policy …` | `KEYS`, `ALGS` or `CLIENT SECRET` in `CREATE ISSUER` | put them in an `oidc_issuer` / `oidc_client` secret and name it with `FROM SECRET` |
| `… accepts no audience - AUDIENCES is required …` | a client without audiences (on it or in its secret) | name the audiences the client's tokens carry |
| `… would accept the same tokens - tell them apart by AUDIENCES, AZP or REQUIRE` | two clients of one issuer overlap where it is visible | narrow one of them |
| `… have the same URL "u" - one IdP is one issuer` | a second issuer for one URL | add a client to the existing issuer instead |
| `… holds an administration scope, so it is mapped FROM CLIENT only` / `ROLES CONSTANT names "r", which holds an administration scope` | a privileged role reached for every client, or as a constant | map it from the one client that may grant it |
| `… has its URL|AUDIENCES|CLIENT ID both on the … and in its secret` | one parameter in two places | keep it in one |

## Not verified

- The exact text of the "requires a quoted value" and "is not allowed" refusals beyond the fragments
  the tests pin.
- A live Entra multi-tenant (`/common`) issuer: its `iss` names the tenant, so it is one issuer per
  tenant until the URL template of a later spec.
