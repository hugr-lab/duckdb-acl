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
- **Platforms**: Linux (GCC), macOS (Clang).

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
make test-integration               # scenarios in test/sql/integration/ (skip w/o scanner or DSN)
```

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
  so a refinement never widens by omission.
- **Capabilities gate both paths**: `select` on every read of a relation (spec 003), the per-verb
  capability (`insert`/`update`/`delete`/`merge`) on DML targets.
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
**Spec 009**: administering the ACL is a granted capability — `acl_grant_admin(role, 'manage'|'passthrough'[, vcat])`
/ `acl_revoke_admin(role)` (or `ACL ADMIN GRANT|REVOKE ADMIN …`), used through
the marker the client writes after the principal prefix: `ACL <mgmt>` (manage the ACL) or
`ACL NATIVE <sql>` (plain SQL outside the virtual catalog — passthrough only); a bare query stays
in the virtual catalog. `ALTER VIRTUAL …` / `ALTER ROLE|ISSUER|GRANT …` change existing objects
(missing target = error). `ACL ADMIN …` is the gateway's anonymous form and needs
`acl_allow_anonymous_admin` once a policy source is enabled.
**Spec 022**: references — declared join paths between objects: `acl_add_reference(vcat, name, from, to,
pairs, expr, cardinality, optional, join_method, comment[, mode])` / `acl_drop_reference`, or
`ACL ADMIN CREATE VIRTUAL REFERENCE c.name FROM a TO b ON (col = col) | ON EXPRESSION '<sql>'
[CARDINALITY …] [OPTIONAL] [JOIN asof] [COMMENT '…']`. A hint an agent reads, never enforced and
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
