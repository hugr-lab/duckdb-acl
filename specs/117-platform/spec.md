# Spec 117: the `platform` catalog - managing a node without native access

- **Status**: implemented (accepted by the owner 2026-10-09, with the recommended answers: authorization arguments are constants, `platform_grants` its own table, a catalog admin sees its catalogs + role names, policy views as SQL, REVOKE ADMIN per bundle, operate/cluster in 118, `platform` absent only on quack; built 2026-10-10 - see *As built*)
- **Date**: 2026-10-09
- **Author**: Claude (design/079 with the owner)
- **Follows**: spec 009 (administration is a capability), 097 (observe), 095 (privileged roles reached only
  through a client's own mapping), 072 (function grants by name), 115 (metadata for tools), 116 (quoted
  names, schema v20). Phase 1 of design/079 (DBeaver as the management console); 118 (node and cluster),
  119 (metadata at scale), 120 (view_as, effective rights, ddl/export) follow.

## Summary

A system virtual catalog **`platform`** answers an administrator's questions and takes its changes
without `ACL NATIVE`: **views** over the policy and the node (typed columns, rows scoped to the caller),
**management functions** `platform.<op>(…)` called at the top level of a statement, and the management
grammar compiled into those functions. Who may read or call what is an **ordinary grant on `platform`'s
objects** (or a built-in bundle of them) - so the tree a tool shows is exactly what the admin may use.
Under a principal prefix the grammar needs no `ACL` marker.

## Problem

Measured on main (design/079 §1): an admin can **write** through a door (`ACL SESSION 'h' ACL <mgmt>`
compiles into `acl_*`), but cannot **read** a single listing - the 24 `acl_*()` listings are in the never
set and answer only in the native context (`passthrough`). A `manage` admin writes blind; a catalog-scoped
one too; listings are not scoped to a catalog; sessions / node load / drain are JSON or text scalars;
caps, columns, audiences, flows, cluster specs are packed JSON/csv inside columns; a pure admin with no
catalog grant sees an empty tree. And a virtual view's COMMENT never reaches `duckdb_views()` /
`information_schema.tables` (the views branch of the tables listing omits it).

## Design

### 1. The catalog
`platform` is **synthesized** - never stored in the policy catalog; the name is reserved (refused by
`CREATE VIRTUAL CATALOG`, every catalog-naming management call, a function-driver source that answers
it; the v21 step fails if a catalog of that name exists). It appears in GetCatalogs / information_schema
/ duckdb_* only for a principal holding at least one grant on it, and only the objects it holds a grant
on. Not on the quack door (quack loads a catalog whole; the console is Flight/JDBC); present under the
gateway's `ACL ROLE` / `ACL TOKEN` and the Flight door. `USE platform` is refused (a session's default
catalog is a data catalog).

### 2. Views (read)
`platform.main.<view>`, substituted before the gate like a metadata surface (`PlatformSurfaceOf` beside
`MetadataSurfaceOf`), each answered by SQL over the policy catalog's tables (filters push down into the
attached scan) or, for node state, an `acl_platform_*` table function. Typed columns - no packed JSON/csv
(`caps` → `STRUCT(select BOOLEAN, insert BOOLEAN, …, manage BOOLEAN)`, a column list → `VARCHAR[]`,
audiences / flows / roles_from → `VARCHAR[]`, requires / attributes → `MAP(VARCHAR, VARCHAR)` or
`STRUCT`, a cluster spec → `MAP(VARCHAR, VARCHAR)`).
Policy: `catalogs, relations, relation_columns, schemas, functions, function_columns, references,
reference_columns, keys, roles, role_claims, grants, schema_grants, object_grants, grant_columns, admins,
issuers, clients, role_mappings, jwks_cache, function_categories, function_category_members,
function_grants, function_status, resource_groups, role_resource_groups, cluster_items,
cluster_effective, catalog_schema, check_findings` (the last a table function: `check_catalog(vcat)`).
Node: `sessions, node_load` (+ `node_doors`, `node_streams`), `drain`, `lineage_status`.
Never a secret (an issuer / client shows the secret's name, as today).

### 3. Functions (write)
`platform.main.<op>(…)` - one per management operation (the `acl_*` writers under their plain names:
`create_catalog`, `add_relation`, `grant_catalog`, `define_issuer`, `map_role`, `grant_admin`, …), named
parameters, typed arguments (STRUCT / LIST where a spec is structured; JSON where it already is the
contract - an issuer / client spec). **Top level only**: `SELECT platform.f(<constants>)` (one item, no
FROM/WHERE/CTE/modifiers) or `CALL platform.f(…)`; anywhere else - in FROM, a subquery, per row of
another selection - refused at rewrite. **Arguments that carry authorization (a catalog, a role, an
object) must be constants** - a parameter there is refused (it cannot be judged before the call); other
arguments may be `?`. Each call is one change, one `admin` audit event, its own policy-catalog
transaction (a client's ROLLBACK does not undo it, as the grammar today).

### 4. The grammar stays the language
Every `ACL <mgmt>` form compiles into its `platform.*` call, and both go through **one authorizer**
(the required right per operation - today's `ProvenanceOf` table, moved into `acl_platform.cpp`), so the
grammar and a direct call are equal in rights, audit and errors. **Under a principal prefix the marker is
not needed** (`GRANT CATALOG sales TO ROLE analyst …`), recognized by the leading phrase
(`IsMgmtStart`); `ACL <mgmt>` still accepted; `ACL ADMIN` (the gateway's anonymous form) and `ACL NATIVE`
(the physical mode) unchanged. A batch mixing management statements and queries is refused.

### 5. Rights = grants on `platform`
- A view is read with `select` on it, rows narrowed by the scope (below); a function is called with a
  grant on it by name.
- Grants live in their own table **`platform_grants(role, object, kind, allowed)`** - never in
  `role_catalogs` / `role_object_caps` / `function_grants` (a `role_catalogs` row for `platform` would
  spread into every listing; a category could hand platform keys to every role).
- **Built-in bundles** (fixed, not editable), `GRANT ADMIN <bundle> TO ROLE r` / `REVOKE ADMIN
  <bundle> FROM ROLE r` (`REVOKE ADMIN FROM ROLE r` - all):
  - `observe` - the node views (`sessions`, `node_load`, `drain`, `lineage_status`), read-only
    (today's `observe`, spec 097);
  - `policy` - the policy views and every policy function except the admin grants (today's
    unrestricted `manage`);
  - `passthrough` - everything, `ACL NATIVE`, grants on `platform` and bundles (the break-glass; stays a
    scope outside the catalog).
  `operate` / `cluster` arrive with spec 118. A catalog admin is `manage` in the grant on the catalog
  itself (spec 009's form): the policy functions taking a catalog check it, the policy views give that
  catalog's rows.
- **Only `passthrough` grants on `platform`** (and bundles) - never `policy`: a grantor that can grant
  everything is everything (the securityadmin lesson, design/079 App. A).
- **Scope of rows**: `policy` / `passthrough` - all; a catalog admin - its catalogs' objects, schemas,
  references, keys, checks, the grants **on** its catalogs, and the **names** of roles holding them (to
  grant to); no identity, categories, resource groups, cluster, node; `observe` - node views only.
- **spec 095 extended**: a role holding any bundle, any grant on `platform` or `manage` on a catalog is
  privileged - reached only through a client's own mapping (never issuer-scope, `AS ROLE` or a
  constant). As today it is judged at use; a mapping written before the grant is caught at the next
  token.
- The `admins` table → primary key `(role, scope, vcat)` (a role holds several bundles). Today's rows
  read as: `observe` → observe; `manage` without a catalog → policy + observe; `manage` with one → that
  catalog; `passthrough` → passthrough. `AdminScope`'s linear order goes: every `>= MANAGE` / `<
  MANAGE` / `!= NONE` site (acl_parser_override.cpp, acl_policy.cpp, acl_admin_sql.cpp,
  acl_identity_store.cpp, acl_node_load.cpp) asks the set instead.

### 6. `platform.console_info()`
The build, the contract versions, the catalog schema and window, the views and functions this node has,
and the caller's own bundles and admin catalogs - what a console reads to show only what works.

### 7. The view comment
The tables listing's view branch carries the view's comment (`TABLE_COMMENT`), so `duckdb_views()`,
`information_schema.tables` and the Flight answers show it; `duckdb_databases.comment` /
`duckdb_schemas.comment` answer the stored catalog / schema comments.

### 8. Schema v21
`platform_grants`; `admins` re-keyed; the reserved name checked. `min_reader_version` 21 (a build
before it does not know the bundles).

## Enforcement & security

- Nothing reachable before is widened: the views answer the same rows `acl_*()` gave passthrough,
  narrowed by scope; the functions are the same writers behind the same authorizer.
- The never set is unchanged: `acl_*` stay uncallable by a principal; `platform.*` is reached only by
  substitution at the top level, judged by the authorizer, never by the function gate.
- No self-escalation: only passthrough grants on `platform`; `policy` cannot grant bundles or admin
  scopes; privileged roles only through a client's own mapping.
- A missing grant fails closed: the object is not listed and the call is refused (`no access`).

## Testing

- `test/sql/platform_views.test` - each view's shape and typed columns; rows per scope (passthrough,
  policy, catalog admin, observe, none - the catalog absent); never a secret.
- `test/sql/platform_calls.test` - every function at top level; refused in FROM / subquery / per row;
  a parameter in an authorization argument refused; audit event per call; the grammar and the call
  give the same result and the same refusal.
- `test/sql/platform_rights.test` - bundles; point grants on a view / function; only passthrough grants
  on platform; spec 095 for a role holding a platform grant (issuer-scope / AS ROLE / constant mapping
  ignored); the old `admins` rows read as bundles after v21.
- `test/sql/platform_markerless.test` - each management form without `ACL` under ROLE / TOKEN / SESSION;
  `ACL <mgmt>` still; mixed batch refused; no data query captured (`COMMENT ON TABLE`, `ANALYZE t`,
  `CREATE FUNCTION`).
- `test/sql/platform_reserved.test` - the name refused everywhere; `USE platform` refused.
- The view comment in `duckdb_views` / `information_schema.tables`.
- Flight e2e: an admin through the door reads `platform.*` (GetCatalogs / GetTables / a view) and calls
  a function, ad-hoc and prepared (spec 111 runs it at GetFlightInfo); a non-admin sees no `platform`.
  Door e2e: no `platform` on quack.

## Alternatives considered

- **`ACL SHOW …` grammar** - no tree, no filters; a sugar over the views at most.
- **DML on the views** (`INSERT INTO platform.roles …`) - a second write surface; batch semantics and
  partial application across rows (design/079 §3.2).
- **Grants stored in role_catalogs / function_grants** - leaks into listings and categories.

## As built (2026-10-10)

- **Where it lives.** `src/acl_platform.{hpp,cpp}`: the registry of the views (`PlatformViews()`, 36:
  the spec's list plus `platform_grants`, `node_doors`, `node_streams`) and of the functions
  (`PlatformFunctions()`: every `acl_*` writer the grammar compiles to, under its plain name, plus the read
  functions), the one authorizer, the compilation of a top-level call, the views' SQL, the listings'
  share and the node-state table functions (`acl_platform_sessions|node_load|node_doors|node_streams`) and
  conversions (`acl_platform_caps|list|map|conditions|attributes`) - all `acl_*`, in the never set,
  reached only by substitution.
- **Typed columns.** caps is `STRUCT(select, insert, update, delete, merge, create, drop, temp, explain,
  secrets, manage BOOLEAN)` - NULL when unstated (a catalog grant: the data capabilities; an object
  grant: inherited); a column list, audiences, azp, roles_from/constant, subject, flows and a function's
  params are `VARCHAR[]`; a client's REQUIRE is `LIST(STRUCT(path, op, values VARCHAR[]))` and its
  ATTRIBUTES `LIST(STRUCT(name, paths VARCHAR[], constant))` - the spec allowed a MAP or a STRUCT; a list
  of structs keeps the order and the several values a condition holds, which a MAP would lose; a cluster
  spec is `MAP(VARCHAR, VARCHAR)`. Each view's SQL ends in a cast to its declared shape, so the listing
  and `DESCRIBE platform.<v>` agree column for column (asserted for every view). `function_columns` is
  `object_columns` of the functions; `check_findings` is the table function `check_catalog([vcat])`
  (`CALL platform.check_catalog(…)` too). Views over the policy tables need a catalog source; in memory
  mode and behind a function driver they refuse with the reason, while the node views, `jwks_cache`, the
  function views, the cluster views and `catalog_schema` (all read through functions) answer.
- **Functions.** Parameter names avoid duckdb's reserved words (`column_name`, `group_name`,
  `into_schema`). A left-out argument (or an explicit NULL) is the target's own fallback, never NULL - the
  admin functions' default NULL handling would make the whole call NULL. A list is accepted where the
  target takes text (`caps := ['select']` becomes the caps JSON, `columns := [...]` the csv). Each call
  answers what its `acl_*` target answers (BOOLEAN, BIGINT, the cluster STRUCT), named after the
  platform function. The compiled call keeps the statement's parameter map, so a `?` in a payload
  argument binds (the golden rule; `test_acl_params_passthrough.cpp`).
- **The authorizer** is spec 009's table as a right per operation (CATALOG / POLICY / HANDS_OUT /
  ESCALATES / INFRASTRUCTURE / OPEN), its refusal texts kept. Three operations the old table did not know
  - `acl_add_reference`, `acl_drop_reference`, `acl_set_key` - were refused to every scope but
  passthrough; they are CATALOG now, as §5 gives a catalog admin its references and keys (the one
  widening, intended). A catalog admin still may not hand out access (`grant_catalog` & co. are
  HANDS_OUT, policy only): spec 009's rule, unchanged - it sees the grants on its catalogs and the role
  names, it does not grant them.
- **Bundles.** `policy` alone reads no node view; spec 009's global `manage` row reads as policy +
  observe, a catalog-scoped one as that catalog, as specified - the rows are kept as written, v21 rewrites
  nothing, and `GRANT ADMIN manage` still writes `manage`. Point grants: `GRANT | DENY VIEW|FUNCTION
  platform.<x> TO ROLE r`, `REVOKE VIEW|FUNCTION platform.<x> FROM ROLE r` (`acl_grant_platform(role,
  kind, object[, allowed])`, `acl_revoke_platform`); a view granted by name is read whole, a function
  granted by name is callable for any catalog and admits the management grammar (`MayAdminister`); never
  to role `''`, never on the passthrough scope's own functions nor on `console_info`; a deny wins over a
  bundle, not over passthrough. `REVOKE ADMIN FROM ROLE r` also removes the role's point grants.
- **spec 095** needed no change of its own: `RolesFor` / `ValidateIdentity` ask `RolePrivileged`, which
  now asks `AdminRights::Privileged()` - any bundle, any point grant (a deny too), a catalog's manage.
- **The grammar** is decided on the batch's first statement past whitespace and comments
  (`StartsWithMgmt` over `SplitBatchText`, which respects quotes, comments, `$tag$` and parentheses), and
  `ParseMgmtBatch` parses statement by statement on the same split - so a comment in front of a
  management statement is now allowed. The mixed-batch refusal applies to `ACL ADMIN` too (it used to be
  `unknown management statement`). `USE platform` is refused before the session check, so under any
  prefix.
- **The function driver**: a `role_catalogs` row naming `platform` refuses every statement of a principal
  holding that role, on every read (nothing of it cached) - fail closed, with the reason.
- **Flight**: a management statement (the grammar bare or marked, a secrets grant) and a top-level
  platform call are commands, run at GetFlightInfo (spec 111), so a client that never fetches keeps the
  change. That exposed a bug: a statement executed at GetFlightInfo whose result has rows (a management
  call, a USE) was opened as a stream at DoGet - refused by duckdb ("a query result that is being
  retained"); a retained result is now read from its handle.
- **Listings**: `platform` appears for a principal holding anything on it - one schema `main`, its views
  as VIEW with their comments and typed columns, its functions in `duckdb_functions()` and
  `acl_function_columns()` - and never on the quack door (`PolicyStore::SessionDoorOf`). The view comment
  fix and the stored catalog / schema comments in `duckdb_databases` / `duckdb_schemas` (NULL for an empty
  one) are §7.
- **The review (2026-10-10) closed three paths to passthrough** the "no self-escalation" rule forbids
  (two of them older than this spec, reachable since spec 009, easy now):
  - *a definition over the policy store itself* - `CREATE VIRTUAL TABLE c.a AS <polcat>.acl.admins`
    plus a grant and an INSERT made a `policy` holder (or a catalog's `manage` with `insert`)
    passthrough. Every writer now refuses a physical target, a schema alias / expansion, a view or
    macro body (the tables it binds to, `query_table` included, else its text), an RLS or a column
    expression that names the policy catalog's tables (`RequireNotPolicyStore`,
    `acl_catalog_admin.cpp`). A secrets service catalog is not covered by this rule (its own
    authorization refuses a principal it does not know as an administrator).
  - *a role mapping to an administering role* - spec 095 admits a privileged role through the client's
    own mapping, so `MAP … TO ROLE <passthrough role>` by a `policy` holder handed the bundle out; it is
    passthrough's now (`AuthorizeRoleTargets`).
  - *a revoke of an implied bundle* (`REVOKE ADMIN policy` from a `manage` row, `observe` from
    passthrough) answered true and changed nothing; it is refused, naming the row to revoke.
  - and the platform functions are refused on the quack door like its views (the grammar stays).
- **The policy admin has no cluster or node operations** (owner's correction, design/079 §3.5): until
  spec 118 adds the `operate` / `cluster` bundles, `session_profile` (PROFILE SESSION) is
  `PlatformRight::OPERATE` and the views `cluster_items` / `cluster_effective` are
  `PlatformViewClass::CLUSTER` - passthrough's alone (a point grant may still give a view; never the
  function); the cluster functions were INFRASTRUCTURE already. Spec 074 had put PROFILE SESSION under an
  unrestricted manage - that narrows here. 118 moves these to operate / cluster. `observe` stays as
  specified (the node views, read-only).
- **The second review round (2026-10-10)**, each with a regression test (`platform_review.test`,
  `test_acl_schema_steps.cpp`, `test_acl_params_passthrough.cpp`):
  - *D1, stored bodies ran as the node*: a view, a macro template, an alias target, an RLS, a column /
    mask expression, a grant's policy, a remap - their function calls were never gated, so a catalog
    admin stored `acl_grant_admin(...)` in a scalar and became passthrough at the first call.
    `AuthorizeBodies` walks every body a compiled call stores (subqueries, CTEs, table functions, PIVOT)
    and judges each call by the AUTHOR's gate (`ResolveFunction` on the author's principal; the never set
    always; markers exempt; a body must be a constant). The anonymous gateway and passthrough stay
    trusted. `acl_check_catalog` adds `body_function_denied` for a body stored before (judged by the
    never set - the author is not recorded).
  - *D2*: `alter_issuer` / `define_issuer` / `alter_client` / `define_client` on an issuer or client that
    carries a mapping to an administering role are passthrough's; so is a catalog `manage` granted (or
    altered in) to a role a mapping reaches - the map-first order.
  - *D3*: the policy store is recognized under every reading the binder may give a name (`<db>.<t>` with
    the policy in `<db>.main`, `<schema>.<t>`, a bare `<t>` in the default path) - over-reading refuses;
    bodies by the tables they bind to, the text when they do not bind.
    Verification round: `ALTER GRANT … SET RLS | COLUMNS` bodies are judged like GRANT's; a schema alias
    / expansion over the policy store's database is refused; so is a schema grant's `INTO` home there
    (a role's `CREATE OR REPLACE` would replace a policy table).
  - *D4*: `IsPlatformCatalog` ignores surrounding whitespace (`"platform "`).
  - a point grant on `check_catalog` admits the grammar too (`MayAdminister`); `SELECT * FROM
    platform.check_catalog(…)` / `CALL` compile to the call `CHECK VIRTUAL CATALOG` is - one `admin`
    event; a refused grammar statement and a call written wrongly are `admin` events of the known
    principal (`mgmt_unauthorized`); a call keeps its column alias and the grammar answers under the
    operation's name; `platform.<x>` that is no platform function is refused by name (never a method call);
    a batch of several `ACL` prefixes has its own message; `REVOKE ADMIN` of a bundle not held is
    refused; `expr AS name` in a COLUMNS list is `name = expr` (it was stored as one name that read
    nothing); `platform_grants.allowed` is NOT NULL (a NULL reads as no grant); the step runner
    substitutes ACL_KEY_TEXT and the generator writes it for every step's key columns (a SQL Server
    catalog could not take step 21's re-keyed `admins`).
  - not changed: the quack door's session lookup stays a scan per batch (cached in the rewriter; the
    listing reads it once per surface).
- **Known**: a virtual schema named `platform` in a MAIN catalog is no longer reached as
  `platform.<x>` (the system catalog takes the two-part name); the v21 step writes plain VARCHAR keys,
  as the earlier steps do (a SQL Server catalog needs the bounded type - the existing step pattern).
- **Not here** (as the spec says): the metadata row limit, the timeout and batching of design/079 §3.2в
  (spec 119), `view_as` / effective rights / ddl (120), `operate` / `cluster` and the node operations
  (118).
- **Gate**: the whole sqllogictest suite, `make test-cpp`, `make schema-check` (20 -> 21), `make
  test-integration`, the Flight e2e (`run`, `adbc`, `stream`, `drain`, `tls`, `auth`, the new `admin`),
  `make test-e2e` (postgres, ducklake, pair; mssql skipped - not built), clang-format 11, the fold and
  thread_local lints, `make tidy` over the changed files (no finding in a changed line).

## Follow-ups

- 118: `operate` / `cluster` bundles, node operations as grammar, drift, `platform.attached.*` +
  `GRANT SOURCE`; `ACL NATIVE` stays the unrestricted break-glass (owner, 2026-10-10).
- 119: the metadata row limit (one GLOBAL, a session may lower it), batching, pushdown + benchmark; a
  timeout only if the benchmark asks.
- 120: `view_as` as a session mode, `effective_rights`, `exposures`, `ddl` / `export_script`, missing
  ALTER / REVOKE.
