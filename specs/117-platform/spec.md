# Spec 117: the `platform` catalog - managing a node without native access

- **Status**: accepted (by the owner 2026-10-09, with the recommended answers: authorization arguments are constants, `platform_grants` its own table, a catalog admin sees its catalogs + role names, policy views as SQL, REVOKE ADMIN per bundle, operate/cluster in 118, `platform` absent only on quack)
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

## Follow-ups

- 118: `operate` / `cluster` bundles, node and cluster operations, `platform.attached.*`, `exposures`.
- 119: metadata limits, timeouts, batching, pushdown + benchmark.
- 120: `view_as`, `effective_rights`, `ddl` / `export_script`, missing ALTER / REVOKE.
