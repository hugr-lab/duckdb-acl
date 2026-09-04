# Serving clients directly

How one node serves clients that connect for themselves: the two doors, the sessions behind them, the
operator's control surface, graceful shutdown, and the invariants a served deployment must hold. The
per-client connection recipes live in [clients/](clients/) and are linked, not repeated; the token
model is [authentication.md](authentication.md); the one-page shape of a node is
[deployment.md](deployment.md).

## Overview

There are two ways a principal reaches the ACL:

- **The gateway deployment** (spec 001). A trusted component owns the DuckDB connection and prepends
  `ACL ROLE "r"` or `ACL TOKEN '<jwt>'` to every statement. The node keeps no state per client; only
  the gateway connects to DuckDB.
- **The doors** (specs 040 onward). A client with an ordinary driver connects to the node itself. It
  cannot prefix its own statements, so the node turns its token into a **session** once, and a door
  puts `ACL SESSION '<handle>'` in front of every statement that connection sends afterwards.

Both doors stand on the same three-function contract (spec 040):

```sql
acl_session_open(token)        -- VARCHAR handle (128 random bits, hex), or NULL if the token does not verify
acl_session_sql(handle, sql)   -- 'ACL SESSION ''<handle>'' ' || sql for a live session, NULL otherwise
acl_session_close(handle)      -- ends it; idempotent
```

A door's whole job is "call `acl_session_sql`, run what it returns, refuse if it is NULL". The door
decides nothing about policy: rights are resolved per statement in the rewriter, exactly as for a
gateway-prefixed statement, and only identity is cached in the handle. The handle is minted from the
OS CSPRNG, never derived from the token, never handed to a client (a Flight client sees a cookie, a
quack client its connection id), and useless outside this instance.

Two doors ship in the extension (built by default on every non-WASM target):

| door | protocol | clients | build switch |
| --- | --- | --- | --- |
| Flight SQL (`acl_flight_serve`) | Arrow Flight SQL over gRPC, TLS native | ADBC, JDBC/DBeaver, Power BI/Fabric | `ACL_NO_FLIGHT=1` leaves it out; the function is then absent |
| quack (`acl_quack_serve`) | DuckDB's own client/server protocol, quack's server compiled into acl | a duckdb process with `ATTACH ... (TYPE quack)` | `ACL_NO_QUACK_EMBED=1` leaves it out; the function then refuses by name |

A build without the Flight door has no `acl_flight_serve` at all; the e2e scripts test for it with
`SELECT count(*) FROM duckdb_functions() WHERE function_name='acl_flight_serve'`.

## Preconditions to open any door

Both `acl_flight_serve` and `acl_quack_serve` run the same check (`RefuseUnlessServable`) before a
socket is touched, so the refusal names the thing to fix. In order:

1. **A policy source is configured** - `acl_use_db(...)` or the function driver.
2. **`acl_allow_anonymous_admin` is off.**
3. **The parser override is STRICT** (`allow_parser_override_extension`; the extension sets it on load
   unless a value was set before).
4. **Cleartext binds loopback only.** Without TLS material the door may bind `localhost`,
   `127.0.0.1`, `::1` or `[::1]` and nothing else. A certificate lifts this rule; so does the quack
   door's explicit `'plain'` mode (a TLS-terminating proxy upstream).

The four refusals, `<fn>` being `acl_flight_serve` or `acl_quack_serve`:

```text
<fn>: no policy source is configured - a served instance resolves every statement against one, so `acl_use_db` (or the function driver) comes first
<fn>: `acl_allow_anonymous_admin` is on, so a served client could administer the ACL with a bare `ACL ADMIN` - turn it off before opening the door
<fn>: the parser override is "<value>", not STRICT - a served statement that failed to parse as ACL would fall through to plain SQL
<fn>: without a TLS certificate the door serves in the clear, so it binds only localhost - pass a cert and key to serve a non-local address, or put a TLS-terminating proxy in front
```

The first three stand regardless of TLS: TLS secures the wire, it does not make an unsafe instance
safe. A typical bootstrap therefore ends its admin block with
`SET GLOBAL acl_allow_anonymous_admin=false;` and only then serves
(`test/e2e/flight/bootstrap.sql`).

## The Flight SQL door

```sql
SELECT acl_flight_serve('grpc://localhost:32700');                        -- cleartext, loopback only
SELECT acl_flight_serve('grpc://0.0.0.0:32700', '/etc/acl/cert.pem', '/etc/acl/key.pem');  -- TLS, any address
SELECT acl_flight_serve('grpc://0.0.0.0:32700', read_text('cert.pem'), read_text('key.pem'));  -- inline PEM
SELECT acl_flight_stop('grpc://localhost:32700');
```

- `acl_flight_serve(uri)` returns the uri it serves. `acl_flight_serve(uri, cert, key)` serves
  `grpc+tls` whatever scheme the uri was written in - the certificate is the intent. Each of `cert`
  and `key` is either inline PEM (recognised by the `-----BEGIN` armor) or a path/URI read through
  duckdb's own filesystem (`read_text`, so an object-store URI rides httpfs). Nothing is written to
  disk. Both arguments are required together: `acl_flight_serve: TLS needs both a certificate and a
  key - acl_flight_serve(uri, cert, key)`. A location that yields nothing is
  `acl_flight_serve: the certificate location "<loc>" holds no single document`; a file that is not
  PEM is `acl_flight_serve: the certificate at "<loc>" is not PEM (no -----BEGIN marker) - pass a PEM
  file/URI or inline PEM text`. A bracketed IPv6 literal (`grpc://[::1]:32700`) parses correctly.
- One door per uri per process: `acl_flight_serve: a door is already listening on <uri>`. A door left
  behind by a database instance that closed without stopping it is reclaimed by the next serve on the
  same uri.
- `acl_flight_stop(uri)` shuts the listener down synchronously, drops every held session connection
  and closes every session of the instance, and returns `<uri> (N session(s) closed)`. It refuses a
  uri nobody serves (`acl_flight_stop: no door of ours is listening on <uri>`) and a door another
  instance opened in the same process (`acl_flight_stop: the door on <uri> belongs to another
  database instance`).
- mTLS is not offered; the token is the client's identity, the certificate is the wire's.

What the door serves, every RPC authenticated per call from the `authorization: Bearer <jwt>` header:

- **Statements as single-use reservations** (spec 047). A query is parsed, rewritten and bound once at
  `GetFlightInfo`; the ticket is an opaque id, redeemable at `DoGet` only by the principal fingerprint
  that made it - a stolen ticket earns nothing. Prepared statements carry the same owner rule, and the
  client's `$1`/`?` are the only parameters in the composed statement (the rewriter adds none), so
  parameter batches bind one-to-one. Text DML rides `DoPut(CommandStatementUpdate)` (JDBC
  `executeUpdate`); `executemany` runs as one batch, rolled back whole on a mid-batch refusal.
- **The catalog RPCs** (spec 046): `GetCatalogs`, `GetDbSchemas`, `GetTables` (with
  `include_schema`), `GetTableTypes`, `GetPrimaryKeys` (declared virtual keys, spec 048),
  `GetImportedKeys`/`GetExportedKeys`/`GetCrossReference` (declared references, spec 022). Every one
  is a `SELECT` over the principal's own `information_schema`, run under the same prefix as a
  statement - there is no second path from the door to the physical catalog. A hidden column is absent
  from the promised schema; a masked column carries the mask's type. `GetSqlInfo` answers build-time
  constants only (`duckdb-acl`, the version, transactions supported, bulk ingestion supported).
- **Bulk ingest** (specs 049/051): `DoPut(CommandStatementIngest)` - ADBC `adbc_ingest`. The stream
  becomes a server-composed `INSERT <named columns> SELECT ... FROM arrow_scan(...)` under an
  `ACL INGEST` prefix only the door writes, so capabilities, the grant's predicate and injected
  columns apply row by row; a refusal anywhere fails the whole statement and nothing lands. Modes:
  `append` (into an existing writable virtual table), `create` (`CREATE TABLE ... AS`, needs `create`
  on a granted schema with a physical home), `replace` (`CREATE OR REPLACE`, priced at
  `create`+`drop`); `create_append` is refused as ambiguous. `acl_max_ingest_rows` caps the rows one
  ingest may stream, enforced while reading. A `transaction_id` on ingest is refused, and so is an
  ingest inside a client's open transaction (the refusal says `inside an open transaction`): the
  ingest owns its own transaction so the row-count cross-check decides before commit.
- **Sessions are cookie-identified connections** (spec 050). The first call of a connection is
  handed a session cookie (Arrow's `arrow_flight_session_id`, minted by our CSPRNG); a client that
  returns it has a durable session backed by a duckdb `Connection` the door holds for the session's
  life. A cookie-less call gets a per-call session closed on the way out - single-call RPCs still
  work, session resources honestly refuse. The token is verified on every call before the cookie is
  honoured; a cookie presented with a different principal's token closes the old session and opens a
  fresh one.
- **Session temp tables**: `CREATE TEMP TABLE` under the explicit `temp` capability of the MAIN
  catalog grant (never in the unstated default). They live in the held connection's private temp
  catalog, resolve by bare name (a virtual name always wins), appear in the session's own
  `SHOW TABLES`/`GetTables`, and are reclaimed by duckdb when the session ends. `adbc_ingest(...,
  temporary=True)` stages into one; a cookie-less call is refused (`lives in the session`).
- **Transactions** (spec 055): `BeginTransaction` opens one on the session's connection and mints a
  `transaction_id`; statements carrying it are validated against the session's own (`acl: unknown
  transaction - it belongs to no open transaction of this session (begin one, or omit the id for
  autocommit)`); `EndTransaction` commits or rolls back. Needs a cookie session (`acl: a transaction
  needs a connection-long session - echo the door's session cookie (a client has one from its second
  call on)`); one at a time (`acl: a transaction is already open on this session - commit or roll it
  back first (savepoints are a follow-up)`). A session that ends mid-transaction is rolled back by
  connection teardown. Use either the protocol's actions or raw `BEGIN`/`COMMIT`, not both.
- **Session options** (spec 068): `SetSessionOptions`/`GetSessionOptions` for `TimeZone` and
  `Calendar` - see [Client-local settings](#client-local-settings).
- **Auth discovery** (spec 064): a `Handshake` whose payload is `discover-auth` answers, without
  credentials, the issuers the node trusts, each issuer's `client_id` and the endpoints the IdP's own
  OIDC discovery names (`token_endpoint`, `device_authorization_endpoint` when present). The same
  document the quack door serves at `/.well-known/quack-auth`.
- **The password handshake** (spec 064): a `Handshake` carrying `authorization: Basic <user:password>`
  becomes the OAuth password grant, run by the node as the issuer's `CLIENT ID` (`acl_define_issuer`
  arguments 8-9, `CREATE|ALTER ISSUER ... CLIENT ID '<id>' [CLIENT SECRET '<secret>']`). The token
  the IdP answers is verified offline like any bearer and returned in the response header
  `authorization: Bearer <token>`, which stock JDBC, ADBC and pyarrow read. The node has no flow
  toggle - the IdP's refusal is the gate (`acl: the IdP at <issuer> refused the password grant: ...`).
  It needs an issuer with a client id (`acl: no issuer here carries a CLIENT ID, so the door cannot
  run the password grant - authenticate with a bearer token instead`) and a TLS door (`acl: the
  password handshake needs a TLS door (acl_flight_serve with a certificate) - refused over
  cleartext`). A payload-less, header-less handshake is a no-op success (spec 058) - the per-call
  bearer stays the only authority.

Refusals a client sees: `acl: authentication failed` for a missing, unverifiable or expired-at-open
token (and nothing more); `acl: node is draining - not accepting new sessions` (gRPC UNAVAILABLE)
for a new client on a draining node; the rewriter's own sentences for policy refusals (`no access to
object ...`, `... does not satisfy the grant ...`, `EXPLAIN needs the explain capability`). A duckdb
exception under any RPC is turned into a named status; `Unexpected error in RPC handling` never
appears (spec 046).

Clients: [DBeaver / JDBC](clients/dbeaver.md), [ADBC (python)](clients/adbc.md),
[Power BI / Fabric](clients/powerbi-fabric.md). The cookie middleware
(`DatabaseOptions.WITH_COOKIE_MIDDLEWARE` in ADBC) is what makes a connection one session.

## The quack door

```sql
SELECT acl_quack_serve('quack:localhost:31700', 'live-server-token');                 -- embedded, discovery on, cleartext, loopback only
SELECT acl_quack_serve('quack:0.0.0.0:31700', token, '/etc/acl/cert.pem', '/etc/acl/key.pem');  -- embedded + TLS, any address
SELECT acl_quack_serve('quack:0.0.0.0:31700', token, 'plain');                        -- bare quack server, cleartext, TLS terminated upstream
SELECT acl_quack_serve('quack:0.0.0.0:31700', token, cert, key, 'embedded');          -- the five-argument form
SELECT acl_quack_stop('quack:localhost:31700');
```

The door is quack's own server compiled into acl (spec 063, `third_party/quack`); it binds the public
address itself, terminates TLS, and speaks the quack protocol with no proxy in between. Argument
shapes: `(uri, token)`, `(uri, token, mode)`, `(uri, token, cert, key)`, `(uri, token, cert, key,
mode)`; `mode` is `'embedded'` (default) or `'plain'`. The uri is quack's `quack:<host>:<port>`
(`:0` picks a free port; the function returns the uri actually bound).

- **The server token is required**, and it is quack's own shared token, not what admits a client -
  the client's JWT is. `acl_quack_serve: pass a server token explicitly. It is not what admits a
  client - their JWT is - but a default-configured quack accepts whatever a caller sends, and this is
  the outer fence around that`.
- **TLS** takes cert and key together (`acl_quack_serve: TLS needs both the certificate and the
  key`), each inline PEM or a location read through duckdb's filesystem, exactly as the Flight door.
  TLS needs a build that carries OpenSSL: `TLS needs a build that carries OpenSSL (the flight build)
  - this build serves cleartext only`. A remote quack client speaks https by default; a loopback one
  stays plain.
- **`mode := 'plain'`** drops the discovery route for a bare, still acl-gated server. It is
  cleartext-only and is the explicit opt-out of the loopback rule for a deployment whose proxy
  terminates TLS; cert/key with it are refused: `acl_quack_serve: 'plain' mode is a cleartext server
  - terminate TLS upstream, or drop the mode to serve TLS here`. Anything else:
  `acl_quack_serve: unknown mode "<m>" (expected 'embedded' or 'plain')`.
- **Discovery**: `GET /.well-known/quack-auth` (http or https, per the door) answers the spec-064
  document, composed from the live policy per request - an issuer added or dropped after the serve is
  advertised at once. While the node drains it answers **503** with body `draining`. A `TYPE quack,
  PROVIDER oidc` secret whose `SCOPE` names the door may omit `ISSUER` and read it from here
  ([clients/quack.md](clients/quack.md)).
- **Bind failures** are named: `acl_quack_serve: a server is already listening on <host:port>`,
  `acl_quack_serve: failed to bind <uri> (address in use, permission denied, or invalid host/port)`.
- **Randomness**: the server mints tokens and session ids from a crypto module. A Flight build serves
  as is (acl registers an OpenSSL-backed `EncryptionUtil` at serve time, only if none is set); a build
  without OpenSSL answers ``acl_quack_serve: the server needs a writable crypto module for its
  token/session RNG - `LOAD httpfs` (the usual choice, also used for JWKS) or `SET
  force_mbedtls_unsafe='true'` before serving. (...)``.
- A build without the embed: `acl_quack_serve: this build was compiled without the embedded door
  (ACL_NO_QUACK_EMBED or WASM)`.

How it enforces: quack calls `acl_quack_authenticate(session_id, client_token, server_token)` once
per connection (it opens a session with the client's JWT and binds it to quack's connection id; a
NULL or false answer is quack's own authentication refusal) and `acl_quack_authorize(connection_id,
query)` per statement, whose VARCHAR return **replaces the executed SQL** - the prefixed statement, or
NULL, which quack turns into its refusal. Both are the defaults of `acl_quack_authentication_function`
/ `acl_quack_authorization_function`, so a plain serve needs no `SET`. quack's own functions
(`quack_serve`, `quack_query`, `quack_active_connections`, `scan_data_from_quack_client`,
`acl_quack_scan_data`, ...) are on the principal denylist. Streamed bulk ingest (`SEND_DATA`) is
generated unprefixed by the server; the parser override recovers the principal from the stream id
(spec 042) and enforces the write as that principal's, and refuses where recovery fails.

**Staging on quack is a granted schema** (spec 056): a quack client's `CREATE TEMP TABLE` is its own
local catalog and an attached catalog cannot hold a temporary object, so the Flight door's session
temp is unreachable from here by construction. Grant a live schema alias `select, insert, create,
drop`; the client creates a table in it, drains into it, promotes with plain SQL, drops it.

**`acl_quack_stop(uri)`** frees the port synchronously and returns a status string rather than an
error: `Stopped listening on <uri> (N session(s) closed)`, or `No server found listening on <uri>
...` when nothing served that uri. The **last-door rule**: quack does not say which listener a
connection arrived at, so sessions are closed only when the instance has no quack door left; with
another still open the answer is `Stopped listening on <uri> (another quack server is still open, so
its sessions stay)`. A stop naming a uri nobody serves is the `No server found` note and nothing
else - nothing of ours closed, so nothing is swept (it used to run the last-door close anyway; fixed
2026-09-03). A door of another instance is refused: `acl_quack_stop: the server on <uri> belongs to
another database instance`.

The embedded server's settings (registered with the door; UBIGINT unless noted):

| setting | default | scope | meaning |
| --- | --- | --- | --- |
| `acl_quack_authentication_function` | `acl_quack_authenticate` | GLOBAL | callback the server SELECTs per connection |
| `acl_quack_authorization_function` | `acl_quack_authorize` | GLOBAL | callback the server SELECTs per statement |
| `acl_quack_server_max_connections` | 1024 | GLOBAL | max concurrent connections |
| `acl_quack_server_keep_alive_timeout` | 300 | GLOBAL | seconds an idle keep-alive connection is kept |
| `acl_quack_cache_max_rows` | 100000 | GLOBAL | rows retained in the result cache (0 = unlimited) |
| `acl_quack_result_ttl` | 3600 | GLOBAL | seconds an idle cached result is kept (0 = never) |
| `acl_quack_prepare_inline_rows` | 24576 | any | rows returned inline in a PREPARE response |
| `acl_quack_target_batch_bytes` | 33554432 | any | target size of one wire batch |
| `acl_quack_rebalance_buffer_bytes` | 0 | any | pending bytes before producers are gated |
| `acl_quack_fetch_producer_buffer_bytes` | 268435456 | any | server-side fetch-ahead cap |
| `acl_quack_enable_reconnects` (BOOLEAN) | false | any | keep the last result until acknowledged |
| `acl_quack_debug_emit_delay_ms` | 0 | any | debug: random delay before a batch is published |

Client recipe: [clients/quack.md](clients/quack.md) (`ATTACH 'quack:<host>:<port>' AS remote (TYPE
quack, TOKEN '<token>')`, or a secret).

## Sessions

A session is opened when a token is verified - by a door or by `acl_session_open` - and ends when:

- it is closed (`acl_session_close`, the driver's `CloseSession`, quack re-authenticating the same
  connection, a door stopping);
- it goes **idle** for `acl_session_idle_timeout` seconds (default 900);
- its token's `exp` passes - **only under `acl_session_token_binding='every_use'`**. Under the default
  `connect`, `exp` is judged at establishment only: an expired token opens nothing, but an open session
  keeps working until idle, close or kill (spec 059; the trade is spelled out in
  [authentication.md](authentication.md));
- an operator kills it (`acl_session_kill`).

Dead records are swept in one pass: explicitly by `acl_session_sweep()`, automatically inside
`SessionOpen` at most once every 60 seconds or whenever the map is at `acl_max_sessions`. At the cap
a new session is **refused**, never an old one evicted - an arriving stranger must not be able to end
somebody's session. On the Flight door each session holds a duckdb connection, so the cap bounds held
connections too.

The operator's surface, on the node's own connection (or through a passthrough admin's `ACL NATIVE`):

```sql
SELECT acl_sessions();            -- JSON: [{"id":"...","subject":"...","roles":[...],"idle_seconds":N,"expires_at":N}, ...]
SELECT acl_session_kill('<id>');  -- BOOLEAN: true if a session with that ops id was ended
SELECT acl_session_count();       -- BIGINT: sessions live right now
SELECT acl_session_sweep();       -- BIGINT: dead records removed
SELECT acl_session_reason('<handle>');  -- 'live' | 'expired' | 'idle' | 'unknown', read-only
```

- `acl_sessions()` never shows the handle (a bearer credential); the `id` is a separate non-secret ops
  id. It lists the records on the node; a record judged dead but not yet swept can still appear, so
  `acl_session_sweep()` first gives the exact live set. `expires_at` is the token's `exp`, raw - under
  `connect` a session may legitimately outlive it.
- `acl_session_kill(id)` ends the session and its bindings; on the Flight door the held connection
  (temp tables, an open transaction) is reclaimed by the door's sweep, and the connection's next call
  is a new session - refused while draining.
- `acl_session_reason(handle)` is for the component that holds the contract: a NULL from
  `acl_session_sql` followed by `expired` means "fetch a fresh token", `idle`/`unknown` mean "reopen
  with the same one" (closed and never-existed both read `unknown`).
- Every one of these, the contract functions and the serve/stop functions are **denied to a
  principal** (`function "acl_session_open" is not allowed`, and likewise for each): a client can
  neither mint a session, compose a prefix, read who else is connected, nor drain the node. A
  client writing `ACL SESSION '...'` into its own query text does not become another principal; a
  dead handle in the prefix is refused as `acl_rewrite: session unknown|expired|idle`.

Settings (all GLOBAL - the store reads them through the instance, so a session-scoped `SET` would
report success and change nothing):

| setting | default | meaning |
| --- | --- | --- |
| `acl_session_idle_timeout` | 900 | seconds a session may go unused before it is dead; `0` disables the rule - refused while the binding is `connect` (`acl_session_idle_timeout=0 would leave no automatic session reaper under acl_session_token_binding='connect' - set the binding to 'every_use' first (spec 059)`) |
| `acl_session_token_binding` | `connect` | `connect` judges `exp` at establishment only; `every_use` re-judges it on every use. GLOBAL-only (`acl_session_token_binding is global - use SET GLOBAL`); other values refused (`acl_session_token_binding accepts 'connect' or 'every_use', not '<v>'`); entering `connect` with idle at 0 is refused (`acl_session_token_binding='connect' needs a live idle reaper: set acl_session_idle_timeout > 0 first (it is currently 0/disabled)`). Memory mode (no policy catalog) stays at `every_use` |
| `acl_max_sessions` | 1000 | sessions that may live at once; at the cap a new one is refused; `0` = unlimited |
| `acl_max_ingest_rows` | 0 | rows one Flight ingest may stream; `0` = unlimited |
| `acl_jwt_clock_skew` | 60 | seconds of skew allowed on JWT `exp`/`nbf` (GLOBAL since the 2026-09-03 review) |
| `acl_version_check_interval` | 1000 | milliseconds between `policy_version` re-reads of the policy catalog (`0` = every batch) |
| `acl_jwks_refresh_interval` | 300 | seconds a fetched JWKS is used before it is read again |
| `acl_jwks_max_stale` | 3600 | seconds a JWKS that can no longer be read may still be used; `0` = a failed read is fatal at once |
| `acl_allow_anonymous_admin` | false | a bare `ACL ADMIN` with no principal; must be off to serve |

## Graceful shutdown (spec 066)

A serving node can be put into **drain**: it stops seating new clients while every established session
keeps working, so in-flight statements, transactions, ingests and fetch streams finish naturally.

```sql
SELECT acl_drain();         -- enter drain; sweeps, then returns the live-session count (BIGINT)
SELECT acl_drain_status();  -- 'serving' | 'draining'
SELECT acl_resume();        -- leave drain; true if it was draining, false if it already served
```

`acl_drain()` is idempotent and **sweeps before counting**: the automatic sweep rides `SessionOpen`,
which drain turns off, so the drain call pays instead and the count it returns is what genuinely
remains. Repeating `acl_drain()` is the watch loop.

What a draining node refuses - every path that turns a stranger into a session goes through one
flag, so a door that forgot to check still could not seat anyone:

- Flight: a new client, and a seated connection re-authenticating as a *different* principal, get
  `acl: node is draining - not accepting new sessions` (UNAVAILABLE - a load balancer and a driver
  both read it as "go elsewhere"). The swap is refused *before* the old session would have closed, so
  drain never ends a session. The password handshake is refused the same way.
- quack: the authentication callback answers NULL, which quack turns into its own refusal;
  `GET /.well-known/quack-auth` answers **503** `draining` - the health-check shape a load balancer
  already watches.
- The contract: `acl_session_open` returns NULL.

What keeps working, deliberately: statements, `BEGIN`, ingest, reservations and stream drains on
established sessions; `ACL TOKEN`/`ACL ROLE` prefixed statements (in the gateway deployment the
gateway is what drains; refusing its statements mid-flight would turn a graceful stop into an outage);
policy administration; `acl_sessions()`, `acl_session_kill`, the serve/stop functions - draining is
when the ops surface is needed most.

The supported stop sequence:

```text
acl_drain()                                  -- new clients now land elsewhere
repeat acl_drain() until 0                   -- the watch loop, or the orchestrator's deadline
acl_session_kill('<id>') ...                 -- stragglers, if the deadline came first
acl_flight_stop(uri) / acl_quack_stop(uri)   -- synchronous teardown
close duckdb / terminate the process
```

Stopping a door closes **every session of the instance**, not only the ones that door served -
sessions are not attributed to a door - so with both doors open, stop them together at the end of
the drain, not one of them mid-way. Stop the doors before closing duckdb: a Flight door left
listening on an instance that closed is a follow-up, not a supported state (a later serve on that
uri reclaims it; terminating the whole process is always safe). The node **never times out by itself**: the deadline belongs to the
orchestrator that is stopping it (`terminationGracePeriod`, `TimeoutStopSec`, a script), which
already has one - a second timer inside the node would add a race, not safety. Drain is runtime
state, not configuration: a restarted node serves; a node that must come up draining calls
`acl_drain()` in its init script before serving. All three functions are denied to a principal.

## Client-local settings (spec 068)

`SET` is refused under a principal except for the two ICU rendering settings, `TimeZone` and
`Calendar` - a `TIMESTAMPTZ` rendered in the server's zone is a wrong answer, not a cosmetic one - and
only where the principal owns its connection. The gate checks four things, and the refusal says which
failed:

- the name is on the allowlist (`SET`, `RESET` and `SET VARIABLE` alike): `SET "<name>" is not
  permitted under ACL: only the client-local rendering settings (TimeZone, Calendar) may be set, and
  only on a session of the client's own`;
- the scope is not GLOBAL: `SET GLOBAL "<name>" is not permitted under ACL: a global setting changes
  the node for every principal - set it for the session`;
- the statement arrived through `ACL SESSION` - a door's client whose session **is** a connection:
  `SET "<name>" needs a session of the client's own (a door's ACL SESSION): a per-statement prefix
  runs on a connection the gateway shares, where a setting would leak to the next principal`;
- the value is a constant: `SET "<name>" takes a constant value under ACL`.

The gateway path may never set one: a gateway shares connections between principals, and a
per-statement `SET` is exactly how one principal's time zone becomes the next principal's wrong
answer. A gateway that wants per-client settings gives its clients sessions.

On the Flight door the protocol's `SetSessionOptions` lands on the same allowlist and the same session
connection (ADBC: `adbc.flight.sql.session.option.TimeZone`); an unlisted name answers
`kInvalidName`, a non-string value or a value duckdb rejects `kInvalidValue`, and it needs a cookie
session (`acl: a session option needs a connection-long session - echo the door's session cookie (a
client has one from its second call on)`). `GetSessionOptions` reads the two back on the session's
connection - the door's read; `current_setting` stays denied to principals. On quack a client's
`SET TimeZone = 'Asia/Tokyo'` is plain SQL through `acl_quack_authorize` and the gate is the whole
mechanism. duckdb autoloads `icu` for the settings themselves.

## Audit and metrics (spec 069)

Every decision the node makes about a principal is one **event**: a statement admitted or refused
(with the objects it touched and the capability judged for each), a management statement, a session
opened / closed / refused, an ingest completed with its row count, a Flight ticket issued / redeemed /
expired / presented by somebody else, the password handshake, a policy reload or source error, a keys
refresh. An event carries who (subject, roles - never a claim value), where (`door`, the session's ops
id - never the handle), what (the statement class - never the text), the verdict, and on a refusal
one `reason_code` from a bounded taxonomy (`no_access`, `capability`, `read_only`, `function_denied`,
`statement_type`, `unchecked_predicate`, `setting_denied`, `parse`, `principal`,
`mgmt_unauthorized`, `ddl_home`, `draining`, `at_capacity`, `source_error`, `unavailable`,
`write_policy`, `policy_error`) plus the refusal text.

- **Levels** - `SET GLOBAL acl_audit_level = 'off' | 'denied' | 'decisions' | 'all'` (default
  `decisions`): refusals only; every statement/admin/ingest decision; plus the session, door, policy
  and keys lifecycle. `acl_session_audit_level(<ops id>, <level>)` overrides it for one live session
  (the operator's call, never the principal's). Whatever the level, the **counters count**: metrics
  are a state of the node, audit is a record of it.
- **Where it goes** - a ring of the last `acl_audit_buffer` events (default 10000), read with
  `acl_audit_events()`; optionally one JSON line per event appended to `acl_audit_sink` (a path or
  URI through duckdb's filesystem, so an object store rides httpfs); and any sink an extension
  registers through `acl_audit.hpp` (the `acl_otel` extension ships OTel logs and metrics). Delivery
  is off the decision path: a bounded queue (`acl_audit_queue`) and one audit thread; when a sink is
  slow the queue drops and **counts** (`acl_audit_dropped()`, `acl.audit.dropped`) - a statement is
  never slowed by its own audit.
- **Metrics** - `acl_metrics()` answers every counter and gauge with its attributes as JSON:
  `acl.decisions{verdict,kind,door,statement}`, `acl.denials{reason_code,door}`,
  `acl.sessions.opened/refused/closed`, `acl.sessions.live`, `acl.door.handshakes`,
  `acl.door.tickets{outcome}`, `acl.ingest.statements`, `acl.admin.statements{scope}`,
  `acl.policy.version/staleness/reloads/writes/source_errors`, `acl.jwks.refreshes/age`,
  `acl.audit.events/dropped/sink_errors/queue_fill/ring_fill`, `acl.node.draining/uptime/info`.
  Attribute values come from bounded sets only - never a role, a subject or an object name.
  `SET GLOBAL acl_metrics_endpoint = true` adds `GET /metrics` (Prometheus text) to the quack door's
  listener, unauthenticated like discovery; 404 while off.
- **Tracing** - a statement's trace rides in the prefix as `TRACE '<correlation id>'` and
  `PARENT '<W3C traceparent>'`, written by whoever composes it: a gateway calling `acl_session_sql`
  sets `acl_correlation_id` / `acl_traceparent` on its connection first; a quack client SETs the same
  two on its own session (spec 068's allowlist); a Flight client sends the `x-correlation-id` and
  `traceparent` headers, or sets them through `SetSessionOptions`. Every event of that statement
  carries both.
- **Node identity** - `acl_node_id` (default `<hostname>:<pid>`) is on every event and metric row, so
  a fleet's streams merge without ambiguity. Nodes never share audit state; a central view is the
  collector's job (spec 069, "In a fleet").

The whole surface - `acl_audit_events()`, `acl_metrics()`, `acl_session_audit_level`,
`acl_audit_flush`, `acl_audit_dropped`, the settings - is the operator's: denied to a principal.

## Deployment invariants and hardening checklist

- **One of two shapes: gateway-only, or doors.** In the gateway deployment only the gateway connects
  to DuckDB. With doors, clients connect to the node and every door composes the prefix itself; a
  client never writes one.
- **STRICT stays on.** The extension sets `allow_parser_override_extension='STRICT'` on load; a
  served instance refuses to start under anything else, because under `DEFAULT`/`FALLBACK` a
  statement that fails to parse as ACL runs as plain SQL with the operator's rights.
- **Anonymous admin off before serving.** `acl_allow_anonymous_admin=true` is the bootstrap's escape
  hatch; end the admin block with `SET GLOBAL acl_allow_anonymous_admin=false;` and only then serve.
- **TLS on a non-local address.** A cleartext door binds loopback only. To leave the machine, pass a
  cert and key (either door) or terminate TLS upstream and use quack's `'plain'` mode. The password
  handshake exists only on a TLS Flight door.
- **The control functions are `acl_`-prefixed and denied to principals.** `acl_*_serve`/`_stop`,
  the session contract, the ops listing and kill, drain/resume - a client cannot reach any of them.
  The operator's path over a door is a `passthrough` admin's `ACL NATIVE <sql>` (spec 009); a
  `manage` admin administers policy through `ACL <mgmt>` but does not leave the virtual catalog.
- **Node-local state.** Sessions, reservations, drain state and the door registries live in this
  process (registries per process, sessions per `DatabaseInstance`). There is no shared session store:
  behind a load balancer, stickiness is the front's cookie, and each node drains on its own.
- **Bound the sessions.** Keep the idle reaper on (`acl_session_idle_timeout` > 0 is mandatory under
  `connect`), size `acl_max_sessions` for held connections, and know that the cap refuses rather than
  evicts - an authenticated attacker can fill it until idle drains it.
- **Choose the token binding knowingly.** `connect` (default) means disabling a user at the IdP ends
  new sessions, not open ones; `every_use` ends them at the next statement at the price of long tokens
  or reconnects.
- **Explicit capabilities only where meant.** `temp` (session temp tables), `explain` (a plan names
  physical objects), `create`/`drop` (ingest create/replace, staging) are never in the unstated
  default; grant them by name.
- **Stop before close.** Drain, watch, kill stragglers, stop the doors, then close duckdb.
- **A ready node to look at**: `test/live/serve.sh [flight|quack|all] [--tls]` seeds a demo policy
  and prints URIs and tokens; `test/live/RUNBOOK.md` walks DBeaver, ADBC and a quack client through it
  (`make serve-flight` / `serve-quack` / `serve-live`). It is a validation rig, not a deployment
  template - its issuer is a fixture HS256 secret.

## Troubleshooting

| you see | it means |
| --- | --- |
| `<fn>: no policy source is configured ...` | serve before `acl_use_db(...)` (or the function driver); configure the policy source first |
| ``<fn>: `acl_allow_anonymous_admin` is on ...`` | the bootstrap escape hatch is still open; `SET GLOBAL acl_allow_anonymous_admin=false` |
| `<fn>: the parser override is "fallback", not STRICT ...` | someone set `allow_parser_override_extension`; `SET GLOBAL allow_parser_override_extension='strict'` |
| `<fn>: without a TLS certificate the door serves in the clear, so it binds only localhost ...` | a non-loopback uri with no cert/key; pass both, or (quack) `'plain'` behind a TLS proxy |
| `acl_flight_serve: TLS needs both a certificate and a key ...` / `acl_quack_serve: TLS needs both the certificate and the key` | one of the two was NULL or empty |
| `... the certificate location "<loc>" holds no single document` / `... at "<loc>" is not PEM ...` | the path is wrong, or points at a non-PEM file |
| `acl_flight_serve: a door is already listening on <uri>` / `acl_quack_serve: a server is already listening on <host:port>` | this process already serves that uri; stop it first |
| `acl_quack_serve: pass a server token explicitly ...` | the second argument is empty |
| `acl_quack_serve: 'plain' mode is a cleartext server ...` | cert/key together with `'plain'`; drop the mode to serve TLS here |
| `acl_quack_serve: the server needs a writable crypto module ...` | a build without OpenSSL; `LOAD httpfs` before serving |
| `acl_*_stop: ... belongs to another database instance` | two instances in one process; stop it from the instance that opened it |
| `acl_flight_stop: no door of ours is listening on <uri>` / `No server found listening on <uri>` | nothing served on that uri (the uri must match what was served); the quack form is a status, not an error, and closes nothing |
| client: `acl: authentication failed` | no `authorization: Bearer` header, a token that does not verify (issuer, signature, audience, `nbf`), or an expired token at session open; the door says no more by design |
| client: `acl: node is draining - not accepting new sessions` / quack discovery `503 draining` | the node is in drain; connect to another node, or `acl_resume()` |
| client: `acl: the password handshake needs a TLS door ...` | BasicAuth on a cleartext Flight door |
| client: `acl: no issuer here carries a CLIENT ID ...` | no issuer has a `CLIENT ID`; add one, or use a bearer |
| client: `acl: the IdP at <issuer> refused the password grant: ...` | the IdP said no (wrong password, or ROPC disabled there) |
| client: `acl: unknown transaction ...` | a stale or foreign `transaction_id`; begin one, or omit it |
| client: `acl: a transaction needs a connection-long session ...` / `acl: a session option needs a connection-long session ...` | the client does not echo the session cookie (ADBC: enable the cookie middleware) |
| client: `no access to object ...` | a physical name, a name outside the grant, or another session's temp table |
| client: `EXPLAIN needs the explain capability` | grant `explain` on the MAIN catalog grant, by name |
| client: `... is not permitted under ACL: only the client-local rendering settings ...` | `SET` of anything but `TimeZone`/`Calendar` |
| client: `SET "<name>" needs a session of the client's own ...` | a `SET` through a gateway prefix; give the client a session |
| `function "acl_session_open" is not allowed` (any `acl_*` control function) | called under a principal; these are the node's, use the node's own connection or `ACL NATIVE` as a passthrough admin |
| `acl_rewrite: session unknown|expired|idle` | a handle in an `ACL SESSION` prefix that is dead; the door should reopen (or the client fetch a fresh token when `expired`) |
| `acl_session_idle_timeout=0 would leave no automatic session reaper ...` | switch the binding to `every_use` first, or keep idle > 0 |
| `acl_session_token_binding is global - use SET GLOBAL` | the setting is GLOBAL-only |
