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
- **DuckDB**: tracks the **2.0 release branch `v2.0-cyanoptera`** (submodule pinned in
  `.gitmodules`; until 2026-09-08 it tracked `main`, which is now `v2.1.0-dev` and already diverges in
  the MERGE INTO API the extension ecosystem builds against). Depends on parser/AST APIs
  (`Identifier`, multi-level `QualifiedName`, `MergeQueryNode`, unified DML query nodes, and since
  2026-09-14 `Literal`) that land with 2.0. **A constant is a `Literal`, not a `Value`**: the
  literal is the text as written and the binder turns it into a value, so build one with
  `ConstantExpression::FromValue(v)` or the `String`/`Integer`/`Null` factories, and read one with
  `GetLiteral().ToValue()` - which returns by value, not by reference. **A result is a `QueryResult`**
  (since the 2026-09-17 pin, duckdb #25477): `MaterializedQueryResult` / `StreamQueryResult` /
  `PendingQueryResult` are gone - `Connection::Query` and `PreparedStatement::Execute` answer a
  retained result (`RowCount`, `GetValue`, `Fetch` read it), `Submit` answers a handle that runs on
  the workers but decides nothing, and a `QueryResultStream` opened on a handle is the one streaming
  form (it refuses a `ResultEagerness::FORCED` statement - a count - which is read from the handle).
  Re-pin to the `v2.0.0` tag when it is cut; the scanners come from the submodule's own
  extension pins (`.github/config/extensions/`), patches included - ducklake's too, since 2026-09-17
  (the three patches we carried in `patches/ducklake/` are upstream). quack is the submodule's own pin
  (#212 - duckdb caught up with our one-commit lead in #25978, 2026-09-22), with the patches duckdb
  carries for it applied to the loadable (`APPLY_PATCHES`) and, by `sync.py`, to the embedded
  server's copies alike (a patch that touches only quack's tests is skipped there, and says so).
- **Dependencies**: none (no vcpkg/OpenSSL). The **shared repository** `duckdb-ext-common` is a
  submodule (spec 076): the audit contract (`contracts/acl_audit.hpp` + `acl_principal.hpp`, the same
  header acl-otel compiles - moved as is, contract version unchanged) and the OIDC client core
  (`oidc/`, compiled into the extension from its source list under OUR namespace,
  `DUCKDB_EXT_COMMON_OIDC_NAMESPACE=acl`, so the names stay `duckdb::acl::oidc::...`; TLS by
  `DUCKDB_EXT_COMMON_OIDC_TLS` in the flight build), and since v0.4.0 `contracts/acl_connection.hpp`
  (spec 078: the session a statement runs under, session open/close observers - tresor's). Pinned to a tag; a change to the contract is a
  PR there first (its charter R4: any layout change bumps `CONTRACT_VERSION`), then a re-pin here.
- **Platforms**: Linux (GCC), macOS (Clang), Windows (MSVC — a release target; CI builds the first two).

## Project structure

```text
src/
  acl_extension.cpp          # entry: model overview, creates the store, calls the registrations
  acl_policy.cpp             # PolicyStore + resolver methods, template cache (the resolver seam)
  acl_policy_catalog.cpp     # the catalog backend's READ path: resolution, gate, rights, caches
  acl_catalog_admin.cpp      #   ... its writers (PolicyStore::Catalog*), acl_metadata_listing.cpp the
  acl_catalog_validation.cpp #   listings, and the probe/bind validators; declared in acl_policy_catalog.hpp
  acl_catalog_maintenance.cpp # spec 039: acl_check_catalog (table function) + acl_repair_relation; seam acl_maintenance.hpp
  acl_rewriter.cpp           # the AST walker; exposes RewriteStatements(...)
  acl_parser_override.cpp    # ACL prefix scanner + parser_override; exposes RegisterAclParser(...)
  acl_admin_functions.cpp    # acl_* admin stubs; exposes RegisterAclAdminFunctions(...)
  acl_door_common.cpp        # what every acl_* scalar and both doors share: StoreOf/RequiredArg, PEM, JSON
  flight/                    # the Flight SQL door (spec 045); seam RegisterAclFlightDoor(...)
  quack_embed/               # the embedded quack server (spec 063) + acl_quack_door.cpp (serve/stop, the
                             #   two callbacks); seam acl_quack_embed.hpp: RegisterAclQuackEmbed/Door(...)
  oidc/                      # acl_quack_auth.cpp (the door's discovery document, spec 062/064) and the quack
                             #   PROVIDER oidc secret (spec 061); the OIDC core itself is duckdb-ext-common's
  include/                   # acl_extension.hpp (AclExtension : Extension) + one header per module
duckdb-ext-common/           # submodule (spec 076): contracts/acl_audit.hpp + acl_principal.hpp, oidc/
test/
  sql/acl.test               # sqllogictest suite (require acl)
  sql/integration/           # scenarios against live databases (make test-integration; skip w/o env)
  cpp/                       # standalone C++ invariant tests (make test-cpp), one main() per file
  harness/                   # runnable end-to-end demo (demo.sql + run.sh)
website/                     # the docs site (Docusaurus): website/docs/*.md are THE user docs, published by
                             #   pages.yml to hugr-lab.github.io/duckdb-acl, built on PRs by docs-build.yml
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
build/release/test/unittest 'test/sql/*'         # run the WHOLE suite (what CI runs; ~50 files)
build/release/test/unittest test/sql/acl.test    # one file (acl.test is the memory-mode baseline only)
GEN=ninja make test-cpp             # standalone C++ invariant tests (specs/002)
make tidy                           # clang-tidy (the repo config) over our sources; needs LLVM's clang-tidy
test/harness/run.sh                 # end-to-end demo against the built extension
test/live/serve.sh [--tls]          # serve one seeded node for real client tools (spec 057 runbook)

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
  and never inherited: `create`/`drop` on a schema (spec 016/051), `temp` (spec 050), `explain`
  (spec 052) and `secrets` (spec 082) on the MAIN catalog grant — each granted by name or not held.
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
- **`PIVOT` / `UNPIVOT` are admitted** (spec 075): the `PivotRef`'s source, aggregates, pivot
  expressions and `IN (SELECT ...)` are walked like any FROM and expression; the implicit form arrives
  as a `MultiStatement` (the parser's `CREATE TEMP TYPE __pivot_enum_* AS ENUM (SELECT DISTINCT ...)`
  per column, then the SELECT) and only that shape is admitted, each enum query rewritten as a read.
- **A grant's projection is probed where it is written** (spec 026): a mask that changes a column's
  type and a computed column the object never had are stored in `grant_columns`, so
  `information_schema.columns` and `DESCRIBE` describe the same thing — what the role reads.
- **Markers baked into template copies**: `acl_claim('<name>')` → claim constant; `acl_arg(n)` → n-th
  call argument's AST. Never registered as real functions ⇒ a missed marker fails closed at bind.
- **Administration is a capability** (spec 009): `{"manage": true}` in a catalog grant (per catalog,
  many catalogs per role, independent of `select`), or a global `manage`/`passthrough` in
  `acl.admins`; never self-escalating, and only `passthrough` leaves the virtual catalog.
- **Golden rule**: the rewriter adds no query parameters — a user's `$1`/`?` is the only parameter.
- **Function gating seam**: `PolicyStore::ResolveFunction` (spec 072) — a call is admitted when its
  key `(database, schema, name, kind)` is in a **category** granted to one of the principal's roles
  (or to `''`, every role) or is granted by name; a deny anywhere wins; a key in no category is
  refused; the **never set** (`acl_*`, `ducklake_*`, `quack_*`, `arrow_scan*`, `query*`,
  `json_execute_serialized_sql`, scanners' `*_query/_execute/_attach`, the engine's `__internal_*`
  helpers) is code and no grant re-opens it. Categories live in the policy catalog
  (`function_categories` / `function_category_members` / `function_grants`, seeded ONCE at creation
  from `schema/function_categories/*.txt` - nothing is ever added automatically after that) or, in
  memory mode, in the seed (`src/acl_function_seed.hpp`, generated). The model
  (`acl_function_categories.hpp`) is built when the policy loads and never reads the source on the
  query path. Every admitted call is emitted **qualified** to its key (`system.main.lower(x)`), so a
  macro named like a builtin in a physical catalog cannot take a principal's call; result columns
  keep the names duckdb gives them (`KeepItemNames`). `acl_function_status([role])` is the operator's
  screen: every function of the node with its categories and status (`never` / `categorized` /
  `uncategorized` - the last is what a freshly loaded extension shows).
- **State is per-instance**: `PolicyStore` reached via `AclParserInfo` (parser) and `AclScalarInfo`
  (admin functions' `function_info`) — no process globals. Every `acl_*` scalar is registered through
  `MarkAclScalar` (fallible **and volatile**): a foldable side effect runs while the optimizer plans
  and may run again at execution; `test/sql/acl_scalar_stability.test` lists any function that forgot.

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
**Spec 071**: `acl_jwks_locations` (GLOBAL only, default `https://`) lists the prefixes a `KEYS FROM`
location - and an issuer's discovery URL (spec 064) - may start with; `..` is refused anywhere; a
location outside it is refused where written and again where read (the node's setting binds,
whatever a shared catalog says; the refusal is the cache row's last attempt and a `keys` event
`location_refused` / `policy_error`, floored); `acl_jwks_cache()` lists what the node trusts
(location, allowed, fetched/tried, error, key count, kids - never keys), `acl_jwks_refresh([issuer])`
drops the cache so the next token re-reads (a read in flight cannot write the old document back).
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
**Spec 039 — catalog maintenance**: the source drifts and nothing on the query path may look (spec 065),
so `acl_check_catalog([vcat])` / `ACL ADMIN CHECK VIRTUAL CATALOG c` (a table function, the operator's,
catalog-scoped under a role's `manage`) probes every stored fact against the source off the query path
and answers one row per finding — `source_missing`, `column_missing`, `definition_broken`, `schema_stale`,
`rls_broken/unchecked`, `grant_column_missing`, `mask_broken`, `schema_missing`, `expansion_stale`,
`reference_dangling` — each with the repair statement to paste. `acl_repair_relation(vcat, vname,
action[, spec])` / `REPAIR VIRTUAL TABLE c.n REMAP (…) | DROP MISSING COLUMNS [AND MASKS]` mends a
declared list: `remap` probes each new expression to bind first; `drop_missing` refuses while an
object grant masks a name it would drop (never a silent loss of protection, spec 038); `AND MASKS`
removes those mask items by name and counts them; a catalog grant's mask is never touched (it
protects the column elsewhere; the object's reads refuse per 038 and the check says `mask_broken`).
The tables listings mark a broken declared-list object in its comment (`acl: broken - declared
column(s) … no longer exist in the source`) by a join, never a probe; the columns surface keeps the
contract as written. A role whose grant masks the vanished column keeps its rows (the mask never
reads it). `MgmtCallName`/`ProvenanceOf` know the one compiled form that is a table function in FROM.

**Spec 008**: `acl_use_functions('{"slot": "fn", ...}')` — the function-driver policy source
(registered table-function callbacks, explicit slot map, read-only); and management SQL —
`ACL ADMIN CREATE VIRTUAL CATALOG / CREATE ROLE / CREATE ISSUER / ADD TABLE|VIEW|SCHEMA|... /
GRANT CATALOG ... TO ROLE ... / MAP GROUP ... / DROP RELATION` — compiled (no parse-time side
effects) into the admin functions; anything else after `ACL ADMIN` stays native passthrough. **Legacy stubs / wrappers**:
`acl_define_token` (memory-only until JWT lands, spec 007), `acl_define_role`, `acl_grant_table`,
`acl_grant_view`, `acl_grant_table_function[,_alias]`, `acl_grant_scalar[,_alias]`,
`acl_deny_function`, `acl_allow_function` — without a catalog they fill the in-memory store; with one
they write the same content into the implicit virtual catalog `default` (the last two are now wrappers
over spec 072's grants by name to every role, for both kinds). **Spec 072** adds the category admin
functions: `acl_create_function_category(name[, comment])`, `acl_drop_function_category(name)`,
`acl_function_category_add/remove(category, members)` (a list or a csv of `[db.schema.]name [TABLE]`),
`acl_grant_function_category(role, category[, allowed])` / `acl_revoke_function_category(role, category)`,
`acl_grant_function(role, spec[, allowed])` / `acl_revoke_function(role, spec)`; role `''` is every
role; the never set is refused where the grant is written, and a member or an admitting grant must
name a function the node has unless its kind is written. The SQL forms: `CREATE | ALTER … ADD|DROP (…)
| DROP [IF EXISTS] FUNCTION CATEGORY c`, `GRANT | DENY | REVOKE FUNCTION [CATEGORY] … TO | FROM ROLE r
| ALL ROLES` (unrestricted `manage` only; see website/docs/management-sql.md).

## Serving clients directly

A gateway prefixes every statement. A client that connects for itself cannot, so a **session** turns a
token into a principal once and a **door** attaches it to every statement after that.

**Spec 040 — the session contract**: `acl_session_open(token)` mints an opaque random handle (or NULL
if the token does not verify; a policy source that throws is a NULL *for a door* - one `session
refused` event with `source_error` and no text out - while `acl_session_open()` itself still raises,
since the gateway is the trusted side and has to know), `acl_session_sql(handle, sql)` returns that SQL with
`ACL SESSION '<handle>'` in front (NULL if the session is unknown, closed or past its `exp` — judged on
every use), `acl_session_close(handle)` ends it. `ACL SESSION '<handle>'` is a fourth prefix kind
alongside ROLE/TOKEN/ADMIN, carrying the same markers. All three functions are denied to a principal:
a client can neither mint a session, compose a prefix, nor close somebody else's. State is in memory
per `DatabaseInstance`; the shared backends a cluster needs are a follow-up.

**Spec 044 — sessions end when nobody ends them**: a door mints one per connection and quack calls
nothing on disconnect, so two rules bound the map. A session dies at its token's `exp` *or* after
`acl_session_idle_timeout` seconds unused (default 900; `0` disables) — `exp` bounds a credential and
says nothing about whether anyone is still there. **Spec 059** relaxes the first rule by default:
`acl_session_token_binding='connect'` (default) judges `exp` only at establishment — an open session
works until idle/close/kill; `'every_use'` restores per-use judgment. `acl_session_sweep()` drops every dead record and
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
`acl_quack_stop(uri)` closes the door and sweeps the sessions it served. quack's own functions are in
spec 072's never set — refused under a principal whatever the data says.
**Spec 062 → 063**: the door is now quack's **server compiled into acl** (`third_party/quack` submodule,
the server object graph in `src/quack_embed/`), replacing the spec-062 loopback front. `AclQuackServer`
binds the public address itself, terminates TLS (`acl_quack_serve(uri, token[, cert, key][, mode])`,
inline PEM or read through the filesystem), and answers `GET /.well-known/quack-auth` from the live
policy — so `ISSUER` in a provider secret (spec 061) is optional when its SCOPE names the door. Its SQL
surface is `acl_quack_*`-named (settings and the `acl_quack_scan_data` drain), so a standalone quack
co-loads without a clash; `mode := 'plain'` raises a bare, discovery-less (still acl-gated) server for
TLS-terminating-upstream deployments. The server's token/session RNG comes from an OpenSSL-backed
`EncryptionUtil` acl registers at serve time (only-if-empty, flight builds), so it needs neither `LOAD
httpfs` nor `force_mbedtls_unsafe` — duckdb's bundled mbedtls RNG is a non-crypto PRNG, unfit for auth
tokens. A namespace-alias shim (`acl_quack_httplib_ns.hpp`) lets quack's
`duckdb_httplib::` sources compile in the OpenSSL httplib namespace; `sync.py` regenerates the few
acl_-renamed TUs on a submodule bump - from a copy carrying duckdb's own quack patches, plus the
embed's one patch: two calls around quack's own statement driver - spec 074's profile arming before
the statement, spec 069's audit hook after it. The driver is quack's delegated collector
(`MakeQuackFetchCollector`: the executor's parallel sink encodes batches and a full stream buffer
parks the producing task) - from 2026-09-17 to 2026-09-22 it was ours, while duckdb ended a failing
delegated query twice (our #25887, fixed in #25978). Measured side by side
(`test/bench/door_stream.py`, spec 063): the full read 1.5x faster than our single-thread drain, and
with our default **`acl_quack_target_batch_bytes` = 8 MiB** (quack's is 32) the early stop costs what
it did: a quack client keeps 64 FETCHes in flight and waits for all of them before its CANCEL on a
LIMIT met, so the first answer of a big result costs 64 batches - LIMIT 1 over 1B rows 0.66 s and
+0.5 GiB at 8 MiB, 2.4 s and +2.3 GiB at 32 (and the client 7.9 GiB; duckdb-quack #277, a client
fix). **Spec 077 - the fetch window** bounds that from the server's side within the protocol: past
the window's batches with rows above the client's ack, a FETCH is answered at once with an EMPTY
batch (a zero-row chunk the client's scan skips) and the produced batches move to the next indices -
decided in index order whatever the arrival order (`AclFetchWindowPlan`, header-only, simulated in
`test/cpp/test_acl_quack_fetch_window.cpp`), the terminal total counting the empties and no empty
after the first terminal, so the client's own batch-count check holds; a FETCH > 65536 above the ack
is refused. An empty answer is HELD while a batch with rows below it is unacknowledged - until it is
produced (a pop wakes it; only when that batch's own FETCH has arrived - one shed at the connection
cap is waited for on the timer), then until the ack moves or 20 ms (doubling to 500 ms while the ack
stays stuck): the client's scan threads each claim their own index, and without the hold they spin empty
FETCHes for as long as a batch takes (a sort: seconds, then MAX_AHEAD fails the query) - #152
shipped without it, the addendum measures both. The window starts at `acl_quack_fetch_window` (8; 0 = quack's behaviour) and doubles per
window acknowledged up to `acl_quack_fetch_window_max` (0 = no cap; equal = fixed): LIMIT 1 over 1B
rows 0.126 s / +55 MiB, the full read unchanged (a fixed 8 halves it - the client decodes a batch per
thread). Four hunks of the FETCH handler in `sync.py`, the window per stream on the session's
connection. GLOBAL for now; a profile per role/token (resource groups) is the follow-up. Many clients at once
(`test/bench/door_concurrent.py`): the door seats ~16 quack clients (`acl_quack_server_max_connections`
1024 / a client's 64 keep-alive connections, one per FETCH in flight); past that quack's pool sheds
connections and queries fail, with or without the window. **Spec 079 - the node's seats**: the connect
handler (a `sync.py` patch) sweeps lapsed leases, counts live connections and asks `AclQuackSeatClaim`
(seated + clients still authenticating, under the store's `quack_seat_lock`) against
`acl_quack_server_max_connections / acl_quack_client_depth` (64; 0 = off) - past it the connect is
refused BEFORE authentication with `acl: node at capacity ...` (session refused, `at_capacity`); a
DISCONNECT or a lapsed lease ends the bound acl session at once (`SessionEndBound`, reasons
client / idle). `acl_node_load()` (`acl_node_load.{hpp,cpp}`) is the load report - sessions per door,
each quack door's seats, draining, admit flags - also `GET /.well-known/acl-node` and the Flight
Handshake payload `node-load`, both behind `acl_metrics_endpoint`. **Spec 080 - the stream budget**:
a producing quack statement reserves (`AclQuackStreamSlot` in the driver patch, inside the `try`
around `Query()`, released when it returns) `acl_quack_stream_reserve_bytes` (0 = producer buffer +
window cap or client depth x batch, 768 MiB default) against `acl_node_stream_budget` (0 = half the
memory limit); a full budget makes the statement WAIT in arrival order (`StreamBudget`, header-only,
tickets; a lone oversized stream is admitted; an abandoned ticket is skipped) up to
`acl_stream_queue_timeout` (25 s - under the quack client's 30 s http_timeout), then fail with the
reason as the stream's error, which PREPARE answers; the load report's `streams` + `admit.new_stream`,
gauges `acl.streams.*`. Flight holds one chunk per stream and does not reserve.
**Spec 084**: the doors' registry (`Servers()`) is never destroyed - a door's connections hold its
instance, and a static map tore the instance down among the static destructors (an attached quack
client's curl destructor on a dead mutex, abort); at exit an `atexit` stops accepting, nothing more,
so an unstopped door's instance gets no final checkpoint - stop the doors before closing.
**Spec 085 - resource groups**: `CREATE RESOURCE GROUP g (window_start|window_max|batch_bytes|
max_result_rows|queue_priority|max_sessions …)` / `GRANT RESOURCE GROUP g TO ROLE r` (unrestricted
manage; schema v15 `resource_groups` + `role_resource_groups`), resolved ONCE at `SessionOpenBody` into
the session's `ResourceLimits` (most generous per limit, 0 = unlimited wins; `max_sessions` charged to
the group allowing most, checked beside `acl_max_sessions`). quack: `AclQuackStatementStarting` puts
them on the door connection (`AclQuackSessionLimits` state + the session-scoped batch setting), the
window and the stream slot read them; `StreamBudget` orders by priority then arrival, +1 level per 5 s
waited. Flight: `MaxResultRowsFor(handle)`. Load report `sessions.by_group`, `acl_sessions()` groups.
The embed is default-on (escape hatch `ACL_NO_QUACK_EMBED`).
Streamed ingest
(`SEND_DATA`): since quack f4328c5 (the duckdb 2.0 pin) the drain statement is composed by the
**client** — `INSERT INTO t SELECT * FROM scan_data_from_quack_client('<id>', NULL::STRUCT(…),
ordered := …)` — and arrives through the door's authorization like any statement, under the
session; spec 042's exemption is keyed by the exact stream id the statement carries (the registry
is the session's own connection), and the rewriter retargets the call to `acl_quack_scan_data`.
The unprefixed fence stays for a stock quack's server-generated drain: it carries no principal and
is refused. Staging on quack is a **granted schema** (spec 056): a client's
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
surface (each session also shows its door, the audit level in force and which of instance / policy /
override decided it - spec 069's addendum, and the answer to acl_otel's spec 004). **Spec 051**: ingest `mode=create`/`replace` builds/replaces a table in a granted physical
home, and `CREATE OR REPLACE` is priced at `create`+`drop` (REPLACE is a drop). **Spec 052**: EXPLAIN
is the explicit `explain` capability (a plan names physical objects); the rest of the leak-audit
surfaces are confirmed fail-closed. **Spec 053**: `acl_flight_serve(uri, cert, key)` serves over TLS
(`grpc+tls`, cert/key inline-PEM or read through duckdb's filesystem) and may bind any address; the
one-arg form stays cleartext-localhost. **Spec 054**: `acl_session_reason(handle)` tells a client why
a session is gone (live/expired/idle/unknown), read-only so it survives the NULL from
`acl_session_sql`. **Spec 055**: transactions live on the session's connection -
`BeginTransaction`/`EndTransaction` open and end one, `transaction_id` is validated against the
session's own, so a driver with autocommit off (DBeaver, ADBC manual-commit) works; ingest still owns
its own transaction. **Spec 064**: auth discovery + the IdP-gated password handshake - the
Handshake payload `discover-auth` answers issuers/client_id/OIDC endpoints unauthenticated
(FlightSqlServerBase seals DoAction), and a BasicAuth handshake becomes the OAuth password grant run
as the issuer's `client_id` (`acl_define_issuer` args 8-9, `CREATE|ALTER ISSUER ... CLIENT ID|SECRET`,
schema v12), the IdP's token verified offline and returned as the connection's bearer; no flow
toggle of ours - the IdP's refusal is the gate; TLS-only by refusal; `acl_issuers()` never lists the
secret.

**Spec 067 — the PEG world**: duckdb's PEG parser is the parser at our pin; `parser_override` is
intact and load-bearing upstream. Foreign syntax under the prefix is a three-way contract, pinned by
`test/cpp/test_acl_foreign_parser.cpp`: bare — a co-loaded extension's token peeler works (loading
acl costs nobody anything); in the virtual context — its opaque `ExtensionStatement` is
default-denied (unenumerable ⇒ unconfinable); under `ACL NATIVE` — works, gated on the passthrough
scope, never the syntax. Grammar-extension registration is not exposed upstream yet; when it lands,
extended-grammar AST flows through the same inner parse (walked or denied per node) and the prefix
itself becomes a grammar rule (design/014 spike; the upstream question is design/011/QUESTION.md).

**Spec 082 — secrets through the ACL** (tresor spec 009's acl side): the node's secrets live in an
attached catalog of type `tresor`, never its own secret manager. Under the explicit `secrets`
capability of the MAIN grant (never implied, not by `manage` either): `ACL GRANT|REVOKE SECRET n TO|FROM
ROLE|GROUP p [FROM|IN c]` compiles in `Prefixed` (ahead of the admin-scope check) to
`c.main.grant_secret('n','role:p',['use'])` / `revoke_secret`; `CREATE [PERSISTENT] SECRET` / `DROP
SECRET` are retargeted to the service (`TEMPORARY` refused, parameters constants only - duckdb evaluates
calls there on the node). `PolicyStore::SecretService(named)` picks the catalog (named, else the one
attached; none/several refused with what to write) from the instance the store keeps since load. A
direct `corp.whoami()` is the function gate's (a category the operator grants); `whoami` is never only
as the system catalog's (quack's), and the resolver reads `x.f` as `x.main.f` when x is no schema.

**Spec 068 — client-local settings**: `SET` stays refused under a principal except the two
render-only settings (`TimeZone`, `Calendar` — one allowlist, `ClientSettingAllowed`), a constant
value, a session scope, and only on a session of the client's own (`Principal::session_connection`,
set by `ACL SESSION` alone): a per-statement prefix runs on a connection the gateway shares, where a
setting would leak to the next principal. The Flight door's `SetSessionOptions`/`GetSessionOptions`
apply the same list on the session's connection. The build carries `icu` for the tests.

**Spec 066 — node drain**: `acl_drain()` stops seating new clients at the one seam they all cross
(`SessionOpen` refuses; the doors say why — Flight answers UNAVAILABLE "draining", quack's discovery
answers 503 `draining`) while established sessions keep working; repeating `acl_drain()` is the
watch loop (it sweeps, then answers what remains - the auto-sweep rode `SessionOpen`, which drain
turns off), stragglers go to `acl_session_kill`, then the doors stop and the process exits. `acl_resume()` / `acl_drain_status()` complete the surface; all three are denied to a
principal. The node never waits or times out by itself — the deadline belongs to the orchestrator.

**Spec 069 — audit and metrics, layered**: every decision is an event (`AuditEvent`, header-only
contract in `acl_audit.hpp` - since spec 076 in `duckdb-ext-common/contracts/`, with `Principal` beside
it in `acl_principal.hpp`): statement/admin (emitted by the parser override after the decision, with
the objects the rewrite touched and the capability judged for each, `rewrite_us`, and on a refusal one
`reason_code` of a bounded taxonomy — the `Reason` enum every `Deny` site names, carried to the
override's catch by a thread-local note), session (open/close/refuse, with door and duration), ingest
(rows, from both doors; quack's drain outcome comes through a `sync.py` patch of the generated server
TU), door (Flight tickets and the password handshake), policy (reloaded/written/source_error, from the
catalog backend's `on_policy`), keys (JWKS refreshed/refresh_failed). The `AuditPipeline`
(`acl_audit_pipeline.hpp`, acl-internal) drains a bounded queue on one thread into registered sinks,
a ring (`acl_audit_events()`) and a JSON-lines file (`acl_audit_sink`); counters are derived from
the events whatever the level, gauges are readers the owners register; `acl_metrics()` answers both,
`GET /metrics` on the quack listener when `acl_metrics_endpoint` is on. Levels
`acl_audit_level` = off/denied/decisions/all, per-session override `acl_session_audit_level`.
Hooks live in the ObjectCache (`AuditHooks`, `GetOrCreate` by type string — no RTTI, no acl
symbol: a loadable extension is RTLD_LOCAL) so `acl_otel` ([hugr-lab/acl-otel](https://github.com/hugr-lab/acl-otel),
the contract in `specs/069-audit/extension-requirements.md`; it pins the SAME duckdb as this repo -
a pin bump here is a bump there the same day) registers sinks and a `SessionPolicy` without
linking acl. The registry is stamped with `AuditHooks::CONTRACT_VERSION` (its first member) and
reached through `AuditHooks::Reach` on both sides: a registry from another header revision is
refused - the base audits on a private one and says so in `acl.audit.contract`, the extension does
not attach. **Bump the version on any change to what `acl_audit.hpp` lays out.** Trace: `TRACE '<id>' [PARENT '<tp>']` prefix markers, composed by every door from
`acl_correlation_id` / `acl_traceparent` (session-scoped, on spec 068's allowlist; a session's
value also lands on its record, since quack composes on a server connection) or Flight's
`x-correlation-id` / `traceparent` headers; each marker once. Never a claim value, a handle or
statement text on an event: a `parse` reason is a fixed sentence, a `principal` reason has its
quoted values blanked, a source's ingest error keeps only its class (`AuditReasonText`,
`AuditIngest`); reasons ≤512 bytes, traces ≤128. `acl_audit_denials_per_second` (100) bounds the
recorded refusals per source (counted regardless). Metric attributes from bounded sets only. The
pipeline's worker never holds the instance (settings and the file are the emitting thread's);
`PolicyStoreHandle`'s destructor in the object cache is the shutdown seam. The gauges' readers run under the registry's lock (ext-common spec 009, v0.7.1): `Remove()` waits for a running snapshot, so a reader must not call back into the gauges nor take a lock held around `Register`/`Remove`.

**Spec 074 — the execution profile**: what the audit decided is one event; what then *happened* is
another - kind `profile`, one per decided statement executed (success or failure), emitted from a
`ClientContextState::QueryEnd` on every connection of the instance (`acl_profile.cpp`; the state
registered at load for the connections already open and by `OnConnectionOpened` after). It carries
`decision_seq` (the statement event's `seq`), `exec_us`, `cpu_us` (thread time summed), rows, bytes,
the memory peaks, `sources[]` (the rollup per attached database the rewrite resolved - `Table` from
the profile matched against the tail of a physical name, never a parse of scanner strings - and per
scanner kind, with the pushdown's *shape*: filters and projections counted, `dynamic_filters` seen)
and `plan[]` (the tree, preorder, ≤256 nodes / depth 32, `truncated` past that; the rollup is over
the whole tree). Never the statement's text, a literal, a path or a claim value - the texts of
`Filters`/`Projections`/`Filename(s)` are counted or ignored. Levels `acl_profile_level` = off
(default) | sampled (the caller's `traceparent` sampled flag) | all, GLOBAL; the level in force for a
statement (`ProfileLevelFor`) is, first answer wins: the operator's override on the session
(`acl_session_profile(id, level)` / `PROFILE SESSION CURRENT | '<id>' ON | SAMPLED | OFF`, unrestricted
manage, `''`/OFF clears; `acl_sessions()` shows `profile_level` + `profile_source`), the registered
`SessionPolicy::ProfileFor` rule, the connection's own `SET SESSION acl_profile_level` (an operator's
connection), the GLOBAL. The note that links execution to decision is the override's
(one per decided statement, with the hash of the statement's text), taken onto the connection by the
batch's first `QueryBegin` and by each statement **whose text matches** - a PREPARE keeps it for the
executions of the prepared text (Flight carries it in the reservation), a statement nobody decided
has no profile, and an unprefixed parse ends what was kept. The profiler is switched per connection
by whoever runs the statement (`ProfileConnectionFor`: the Flight door before each execution, quack's
driver before it submits, `QueryBegin` on the gateway path) and never over a client's own setting.
Contract `AuditHooks::CONTRACT_VERSION` = 2. duckdb resets the profiler at an autocommit rollback
before any hook: a failed statement's profile has its outcome, class and wall time, not the tree.

**Spec 078 — the acl_connection contract** (duckdb-ext-common spec 005, `contracts/acl_connection.hpp`,
magic `ACLC` v2 since spec 081 / tag v0.6.0; consumer tresor's delegation): `AclConnection` (a ClientContextState,
key `acl_connection`) names the session a statement runs under - published at QueryBegin from the
override's note (`proto.session`, set only by `ACL SESSION`; the note carries opened/expires from
`SessionRefOf`) and withdrawn at QueryEnd whatever ended it, so a gateway's shared connection never
shows one principal's session to the next; `AclSessionHooks` (ObjectCache) holds `SessionObserver`s
that `SessionNotifier` (`acl_session_hooks.{hpp,cpp}`, a store member) calls: `OnSessionOpen` after
verification, before the handle is returned, outside the store lock, the verified token by reference
for the call only; `OnSessionClose` exactly once per open, after it (a close racing its open waits),
queued in `SessionClosed` - every removal's seam - and flushed after the lock by
`DeliverSessionNotices` declared before each closing method's lock_guard; reasons client / idle /
expired / killed / door_stopped / shutdown (the store's destructor). An observer that throws is
counted, never fails an open; gauges `acl.sessions.observers` (-1 = another contract version),
`.observer_failures`, `.observer_slow` (>100 ms). Never the handle, never a stored token. **Spec 081**: acl marks the
registry at load (`MarkPublisher("duckdb-acl <build> (ACLC 2)")`), so a consumer that must act for
sessions refuses on a node where nobody publishes them.

**Spec 070 — the Flight door streams**: `DoGet` submits the statement (`PreparedStatement::Submit`,
a handle; a `ResultEagerness::FORCED` statement - a count - runs to completion instead) and hands
gRPC a `RecordBatchStream` over `AclResultReader`, which pulls ONE duckdb chunk per Arrow batch
through the `QueryResultStream` opened on the handle — nothing beyond the chunk in flight is held,
whatever the result's size. The stream lives in a
slot (`FlightDoorState::ResultStream`) the reader and the session connection share: every pull takes
`SessionConn::exec` + `stream_lock` and releases them, so the session's next statement
(`LockForStatement`, every former `lock_guard(exec)` site) can end a stream that sat unpulled for
`acl_flight_stream_idle` seconds (30; 0 = never, the statement waits) from its own thread — interrupt,
`Close()` (what releases duckdb's active query; the destructor does it too since the unified
`QueryResult`, but the slot outlives its reader, so it is done where the outcome is known), drop the
result, mark the slot `superseded` — while one being pulled makes it wait. A pull touches the session
(`SessionTouch`) and a killed/expired durable session ends its stream at the next pull. Whatever ends
the stream interrupts and closes the query (duckdb's own LIMIT rule): consumed, cancelled (gRPC
destroys the reader — its destructor — or `is_cancelled()` between pulls), superseded, capped
(`acl_max_result_rows`, 0 = unlimited: exactly N rows out, then the refusal, reason `at_capacity`),
failed (`source_error`; the client gets the text, the audit its class; a partial result is an error,
never a short one). Schema and batches are built from ONE `ClientProperties` snapshot taken under
`exec` at execute. One `door` event `stream_<outcome>` with rows per stream, counter `acl.door.streams`
(also `ingest_cancelled`), gauge `acl.door.streams_open`. Ingest mirrors it: `IngestGetNext` checks
`is_cancelled()` between batches AND at end of stream (a dead client reads as a clean half-close), a
client that dies rolls the load back (`ingest` event `denied/unavailable`, `door` event
`ingest_cancelled`). The e2e is `test/e2e/flight/stream.sh` (pyarrow client; server answers read
through its own stdin) — the 200M-row view, the ms to the first batch, and each outcome.

## Security testing is part of development here

duckdb-acl is an access-control product, and we are its authors. Verifying enforcement means running
queries as a restricted principal and checking that the gate refuses what it must: functions,
macros, catalog listings, paths. A gap found this way is a bug in our own code - it gets a fix, a
regression test that fails without the fix, and a line in the relevant spec. Probe results live in
tests and specs, never as standalone "how to extract data" notes. Name things for what they check:
a "gate coverage probe" or a "negative test", not an exploit.

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
