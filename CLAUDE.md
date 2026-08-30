# duckdb-acl — Development Guidelines

Role/token-scoped access control for DuckDB, implemented as a **`parser_override`** that rewrites the
query AST **before bind**. A trusted gateway prepends an `ACL` prefix to every query; the extension
verifies the principal, resolves virtual names to physical objects, applies row-level security and
column masking, gates functions, and returns real `SQLStatement`s to the normal
bind → optimize → execute path.

Read **[specs/001-parser-override-ast-rewrite/spec.md](specs/001-parser-override-ast-rewrite/spec.md)**
for the core model. Deeper research/thinking lives in a local `design/` folder (gitignored).

## Technology

- **Language**: C++17 (DuckDB extension standard).
- **DuckDB**: tracks **`main`** (submodule pinned in `.gitmodules`); depends on parser/AST APIs
  (`Identifier`, multi-level `QualifiedName`, `MergeQueryNode`, unified DML query nodes) not yet in a
  stable release. Re-pin to a tag once those land.
- **Dependencies**: none (no vcpkg/OpenSSL).
- **Platforms**: Linux (GCC), macOS (Clang), Windows (MSVC — a release target; CI builds the first two).

## Project structure

```text
src/
  acl_extension.cpp          # entry: model overview, creates the store, calls the registrations
  acl_policy.cpp             # PolicyStore + resolver methods, template cache (the resolver seam)
  acl_rewriter.cpp           # the AST walker; exposes RewriteStatements(...)
  acl_parser_override.cpp    # ACL prefix scanner + parser_override; exposes RegisterAclParser(...)
  acl_admin_functions.cpp    # acl_* admin stubs; exposes RegisterAclAdminFunctions(...)
  include/                   # acl_extension.hpp (AclExtension : Extension) + one header per module
test/
  sql/acl.test               # sqllogictest suite (require acl)
  sql/integration/           # scenarios against live databases (make test-integration; skip w/o env)
  cpp/                       # standalone C++ invariant tests (make test-cpp), one main() per file
  harness/                   # runnable end-to-end demo (demo.sql + run.sh)
docker/                      # integration databases: compose + per-DB init SQL (specs/005)
specs/                       # one lightweight spec per feature, NNN-slug/spec.md (see specs/README.md)
design/                      # LOCAL, gitignored: numbered research topics NNN-topic/ (our scratch)
```

Internals live in `namespace duckdb::acl` (spec 004); only `AclExtension` sits directly in `duckdb`.
Each module exposes one seam (`RegisterAclParser`, `RegisterAclAdminFunctions`, `RewriteStatements`,
the `PolicyStore` types); TU-local code stays in anonymous namespaces.

## Commands

```sh
git submodule update --init --recursive
GEN=ninja make                      # release build of duckdb + the extension
build/release/test/unittest test/sql/acl.test    # run the suite
GEN=ninja make test                 # same, via the ci-tools target
GEN=ninja make test-cpp             # standalone C++ invariant tests (specs/002)
test/harness/run.sh                 # end-to-end demo against the built extension

# integration (specs/005): real DBs in docker + scanner-backed scenarios
cp .env.example .env                # once
make vcpkg-setup                    # once: scanner dependencies come from vcpkg (merged manifests)
make docker-up                      # postgres + mysql + sqlserver (initialized)
ACL_INTEGRATION=1 GEN=ninja make    # build incl. postgres_scanner/ducklake
ACL_QUACK=1 GEN=ninja make          # build incl. quack (spec 041): the live door test needs it
make test-integration               # scenarios in test/sql/integration/ (skip w/o scanner or DSN)
```

CI builds the linux job with both flags, so the served round trip is exercised on every PR; the
macOS job builds neither and runs the plain suite.

Build outputs: CLI `build/release/duckdb`, loadable
`build/release/extension/acl/acl.duckdb_extension`, test binary `build/release/test/unittest`.
The extension enables its own parser override on load (`allow_parser_override_extension='STRICT'`,
spec 017); an explicit value set before loading is left alone, and `SET GLOBAL ...='DEFAULT'` turns
enforcement off — the `acl_*` functions still configure policy, but no `ACL …` statement parses.

## Code style

- Follow DuckDB's conventions: tabs for indentation, ≤120 columns, `[u]int(8..64)_t` and `idx_t`,
  `unique_ptr`/`optional_ptr`/`reference`, never raw pointers or `const_cast`, braces always, short
  comments. Run `clang-format` (the repo `.clang-format`) before committing.
- Names: files `snake_case`, types `PascalCase`, functions `PascalCase`, variables `snake_case`.
- Prefer sqllogictest (`test/sql/*.test`) over C++ tests. Every feature lands with tests.

## Key concepts (see DESIGN.md for detail)

- **Two replacement forms**: RENAME (name → physical in place, writable) vs SUBQUERY (wrap a SELECT:
  projection/masks/computed columns/RLS/view SQL, read-only). The resolver picks per object.
- **Unstated caps = every data capability** (spec 012): a grant written without `CAPS` — or a driver
  row with NULL/empty caps — means `select, insert, update, delete, merge`, never `manage`; an
  explicit `'{}'` means none. An *object* grant that states nothing inherits the catalog grant's caps,
  so a refinement never widens by omission. The capabilities *outside* that default are explicit-only
  and never inherited: `create`/`drop` on a schema (spec 016/051), `temp` (spec 050) and `explain`
  (spec 052) on the MAIN catalog grant — each granted by name or not held.
- **A grant's predicate confines writes too** (spec 024): it is AND-ed into the read/write `WHERE` and
  also checked against the row being written — an `INSERT`/`UPDATE`/`MERGE` that would leave a row
  outside the principal's slice is refused where the value is written (`error()` inside a `CASE`). An
  insert under a predicate must name its columns and supply what the predicate reads; an injected
  value satisfies it by construction.
- **Capabilities gate both paths**: `select` on every read of a relation (spec 003), the per-verb
  capability (`insert`/`update`/`delete`/`merge`) on DML targets.
- **`DESCRIBE` / `SUMMARIZE` / `SHOW TABLES` are answered** (spec 025): `DESCRIBE <name>` becomes
  `DESCRIBE (SELECT * FROM <name>)`, so the description is of the rewritten relation — a hidden column
  is hidden from it too; `SHOW TABLES [FROM s]` is the principal's `information_schema.tables` in the
  shape `SHOW TABLES` returns.
- **A grant's projection is probed where it is written** (spec 026): a mask that changes a column's
  type and a computed column the object never had are stored in `grant_columns`, so
  `information_schema.columns` and `DESCRIBE` describe the same thing — what the role reads.
- **Markers baked into template copies**: `acl_claim('<name>')` → claim constant; `acl_arg(n)` → n-th
  call argument's AST. Never registered as real functions ⇒ a missed marker fails closed at bind.
- **Administration is a capability** (spec 009): `{"manage": true}` in a catalog grant (per catalog,
  many catalogs per role, independent of `select`), or a global `manage`/`passthrough` in
  `acl.admins`; never self-escalating, and only `passthrough` leaves the virtual catalog.
- **Golden rule**: the rewriter adds no query parameters — a user's `$1`/`?` is the only parameter.
- **Function gating seam**: `PolicyStore::FunctionAllowed` — denies only data-readers / rights-bypass
  functions, passes the rest. This is where a production role-aware resolver plugs in.
- **State is per-instance**: `PolicyStore` reached via `AclParserInfo` (parser) and `AclScalarInfo`
  (admin functions' `function_info`) — no process globals.

## Admin / setup functions

Two layers (spec 006). **Catalog model**: `acl_use_db(name[,schema[,init]])` switches the store to a
policy catalog in any ATTACHed database (standard duckdb dialect only, source agnostic);
`acl_create_catalog`, `acl_add_relation/_view/_schema_alias/_table_function[_alias]/_scalar[_alias]`,
`acl_grant_catalog(role, vcat, caps_json, is_main)`, `acl_revoke_catalog`, `acl_drop_relation`.
Settings `acl_version_check_interval` (policy staleness) and `acl_jwt_clock_skew` (JWT exp/nbf).
**JWT** (spec 007): `acl_define_issuer(issuer, keys_json, audiences, algs, role_claim, claim_map)`
and `acl_map_role(issuer, source, external, role)` — a JWT-shaped `ACL TOKEN` verifies offline
(RS256/ES256/HS256; mbedtls + vendored p256-m), roles resolve as a multi-role union.
**Spec 023**: an issuer may name a document to read its keys from instead of pasting them —
`KEYS FROM '<uri>'` (or the 7th argument of `acl_define_issuer`), read through duckdb's own filesystem,
so an https JWKS (needs httpfs) and a file refreshed out of band are one mechanism. Cached per
instance: `acl_jwks_refresh_interval` (300s), a re-read when a token names an unknown `kid`, and
`acl_jwks_max_stale` (3600s; `0` = a failed read is fatal at once). Keys and location are alternatives.
**Spec 009**: administering the ACL is a granted capability — `acl_grant_admin(role, 'manage'|'passthrough'[, vcat])`
/ `acl_revoke_admin(role)` (or `ACL ADMIN GRANT|REVOKE ADMIN …`), used through
the marker the client writes after the principal prefix: `ACL <mgmt>` (manage the ACL) or
`ACL NATIVE <sql>` (plain SQL outside the virtual catalog — passthrough only); a bare query stays
in the virtual catalog. `ALTER VIRTUAL …` / `ALTER ROLE|ISSUER|GRANT …` change existing objects
(missing target = error). `ACL ADMIN …` is the gateway's anonymous form and needs
`acl_allow_anonymous_admin` once a policy source is enabled.
**Spec 022**: references — declared join paths between objects: `acl_add_reference(vcat, name, from, to,
pairs, expr, cardinality, optional, join_method, comment[, mode])` / `acl_drop_reference`, or
`ACL ADMIN CREATE VIRTUAL REFERENCE c.name FROM a TO [FUNCTION] b ON (col = col) | ON EXPRESSION '<sql>'
[CARDINALITY …] [OPTIONAL] [JOIN asof] [COMMENT '…']`. An end may be a table, a view or a table
function; for a function the parenthesis after its name is the argument substitution
(`TO FUNCTION f(param => col)`, checked against the declared signature) and `ON` is the join condition
on its result — either may stand alone. A hint an agent reads, never enforced and
granting nothing; visible only when both ends and every column it names are. A principal reads its own
through `acl_references([object])`, substituted before the function gate.
**Spec 008**: `acl_use_functions('{"slot": "fn", ...}')` — the function-driver policy source
(registered table-function callbacks, explicit slot map, read-only); and management SQL —
`ACL ADMIN CREATE VIRTUAL CATALOG / CREATE ROLE / CREATE ISSUER / ADD TABLE|VIEW|SCHEMA|... /
GRANT CATALOG ... TO ROLE ... / MAP GROUP ... / DROP RELATION` — compiled (no parse-time side
effects) into the admin functions; anything else after `ACL ADMIN` stays native passthrough. **Legacy stubs / wrappers**:
`acl_define_token` (memory-only until JWT lands, spec 007), `acl_define_role`, `acl_grant_table`,
`acl_grant_view`, `acl_grant_table_function[,_alias]`, `acl_grant_scalar[,_alias]`,
`acl_deny_function`, `acl_allow_function` — without a catalog they fill the in-memory store; with one
they write the same content into the implicit virtual catalog `default`.

## Serving clients directly

A gateway prefixes every statement. A client that connects for itself cannot, so a **session** turns a
token into a principal once and a **door** attaches it to every statement after that.

**Spec 040 — the session contract**: `acl_session_open(token)` mints an opaque random handle (or NULL
if the token does not verify), `acl_session_sql(handle, sql)` returns that SQL with
`ACL SESSION '<handle>'` in front (NULL if the session is unknown, closed or past its `exp` — judged on
every use), `acl_session_close(handle)` ends it. `ACL SESSION '<handle>'` is a fourth prefix kind
alongside ROLE/TOKEN/ADMIN, carrying the same markers. All three functions are denied to a principal:
a client can neither mint a session, compose a prefix, nor close somebody else's. State is in memory
per `DatabaseInstance`; the shared backends a cluster needs are a follow-up.

**Spec 044 — sessions end when nobody ends them**: a door mints one per connection and quack calls
nothing on disconnect, so two rules bound the map. A session dies at its token's `exp` *or* after
`acl_session_idle_timeout` seconds unused (default 900; `0` disables) — `exp` bounds a credential and
says nothing about whether anyone is still there. `acl_session_sweep()` drops every dead record and
returns how many; `SessionOpen` runs the same pass by itself, at most once a minute or whenever the map
is at `acl_max_sessions` (default 1000; `0` unlimited). At the cap a new session is **refused**, never
an old one evicted — making room by ending somebody's session is the worse failure. `acl_session_count()`
reports the live total; both new functions are the door's, not a principal's.

**Spec 041 — the quack door**: quack calls an authentication function per connection and an
authorization function per statement **whose VARCHAR return replaces the executed SQL**, so serving
under the ACL is two thin wrappers over the contract: `acl_quack_authenticate(session_id, client_token,
server_token)` opens a session and binds it to the connection, `acl_quack_authorize(connection_id,
query)` composes the prefix or answers NULL, which quack turns into a refusal. `acl_quack_serve(uri,
token)` installs both and starts the listener, refusing an instance a client could step out of
(anonymous admin on, override not `STRICT`, no server token, quack not loaded);
`acl_quack_stop(uri)` closes the door and sweeps the sessions it served. quack's own fourteen functions
are on the denylist — the gate is a denylist, so a loaded extension widens the surface until named.
quack listens in the clear: a served deployment sits behind a reverse proxy. Streamed ingest
(`SEND_DATA`) is generated **unprefixed** by the server; spec 042 recovers the principal from the
stream id the statement itself carries and enforces the write as that principal's — the refusal
remains only where recovery fails. Staging on quack is a **granted schema** (spec 056): a client's
`CREATE TEMP` is its own local catalog and an attached catalog cannot hold one, so the Flight door's
server-side temp (spec 050) is unreachable from here by construction — CREATE/drain/promote/DROP
through specs 016/042/051 is the pattern instead.

**Specs 045–053 — the Flight SQL door**: `acl_flight_serve(uri[, cert, key])` / `acl_flight_stop(uri)`
serve the
protocol ADBC and JDBC drivers speak. A statement is a single-use **reservation** (spec 047): parsed,
rewritten and bound once at GetFlightInfo, redeemable at DoGet only by the principal fingerprint that
made it. The catalog RPCs answer the principal's catalog (spec 046), bulk ingest appends under an
`ACL INGEST` prefix only the door composes (spec 049). **Spec 050**: a session IS a duckdb
connection — identified by the door's own CSPRNG cookie (a cookie-less call gets a per-call session;
a client has a durable one from its second call on), held as a `Connection` per session and executed
on under a per-session lock. On it, **session temp tables**: `CREATE TEMP TABLE` under the explicit
`temp` capability of the MAIN catalog grant (never in the unstated default), bare names resolve
virtual-first then via a direct no-transaction read of the connection's temp catalog (the thread-local
exec-context seam the door sets around Prepare; without it — quack — the rewriter temp-qualifies and
the bind decides), DML/DROP are symmetric, `SHOW TABLES`/tables listings include the session's own
temps, and ingest `temporary = true` stages into a session temp the client then moves with plain SQL.
duckdb reclaims everything with the connection; `acl_sessions()` / `acl_session_kill(id)` are the ops
surface. **Spec 051**: ingest `mode=create`/`replace` builds/replaces a table in a granted physical
home, and `CREATE OR REPLACE` is priced at `create`+`drop` (REPLACE is a drop). **Spec 052**: EXPLAIN
is the explicit `explain` capability (a plan names physical objects); the rest of the leak-audit
surfaces are confirmed fail-closed. **Spec 053**: `acl_flight_serve(uri, cert, key)` serves over TLS
(`grpc+tls`, cert/key inline-PEM or read through duckdb's filesystem) and may bind any address; the
one-arg form stays cleartext-localhost. **Spec 054**: `acl_session_reason(handle)` tells a client why
a session is gone (live/expired/idle/unknown), read-only so it survives the NULL from
`acl_session_sql`. **Spec 055**: transactions live on the session's connection -
`BeginTransaction`/`EndTransaction` open and end one, `transaction_id` is validated against the
session's own, so a driver with autocommit off (DBeaver, ADBC manual-commit) works; ingest still owns
its own transaction.

## Working process — per-feature specs

We do **not** run full spec-kit. Instead, each feature gets one lightweight spec under `specs/` (see
**[specs/README.md](specs/README.md)**):

1. Before (or alongside) implementing a feature, create `specs/NNN-slug/spec.md` from
   `specs/TEMPLATE.md` — problem, design, enforcement/security, tests, alternatives.
2. Implement with tests; keep the spec updated; set its status to `implemented` when done.
3. Reference the spec in the commit/PR.

Keep specs short and honest. When a decision changes, update the spec or supersede it with a new one.
`design/` (gitignored) is our scratch space for the research behind a spec.

## Gateway

Deployment invariant: **only the gateway connects to DuckDB.** A reference Arrow Flight SQL gateway
(embedding DuckDB, doing JWT introspection → role/claims, prefixing, token-masking) is a separate repo.
