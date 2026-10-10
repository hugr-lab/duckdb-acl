# Spec 118: node and cluster management - operate / cluster, drift, the physical tree

- **Status**: accepted (by the owner 2026-10-10); **118.1 implemented** (see *As built*); aligned after the comparison with Trino, Snowflake, Databricks UC,
  ClickHouse, PostgreSQL, SQL Server - design/079 App. A)
- **Date**: 2026-10-10
- **Author**: Claude (design/079 with the owner)
- **Follows**: spec 117 (the platform catalog, its authorizer and bundles), 093 (cluster profile), 096 (a node's
  resource group), 066 (drain), 097 (observe), 082 (secrets through the ACL), 116 (names). Phase 1 of
  design/079.

## Summary

Two more built-in bundles of spec 117 - **`operate`** (a node's runtime: sessions, drain, load) and
**`cluster`** (operate + the cluster profile, drift and the physical tree's metadata, never data) -
the node operations as grammar, and the physical tree as metadata under `platform.attached`, where a
catalog admin sees only the sources granted to it (`GRANT SOURCE`). **`ACL NATIVE` stays the
break-glass and is not restricted** (owner, 2026-10-10): whatever an operator could type in a native
console works there; what makes a node differ from its profile is shown (drift, audit), never refused.

## Problem

- Node runtime (kill, audit level, profile, drain, resume) and the cluster profile are passthrough-only:
  the orchestrator's drain token and the platform engineer who attaches sources both hold data access
  (`ACL NATIVE`). Every system in design/079 App. A separates these.
- A one-off ATTACH / INSTALL / SET GLOBAL on one node (break-glass) unbalances a cluster - and nothing
  shows it.
- Node operations have no grammar (only `acl_*` calls, native only).
- No admin can see the physical tree without `ACL NATIVE`; a catalog admin cannot be confined to the
  sources it may build on.
- A standalone node without a secrets service cannot keep a secret under a principal (082 refuses).
- Found in research: the cluster DETACH check ignores a virtual view's SQL - a view over a source does
  not block its DETACH.

## Stages (owner, 2026-10-10: one after another, a PR each with its own reviews)

1. **118.1 - the node**: `operate`; KILL SESSION / SET SESSION … AUDIT LEVEL / DRAIN / RESUME NODE;
   secrets on a standalone node without tresor; a view over a source blocks its DETACH;
   `platform.audit_events`.
2. **118.2 - the cluster**: `acl_deployment`; `cluster`; drift; the cluster parts in their own files (to
   move to hugr_node).
3. **118.3 - the physical tree**: `platform.attached.*` (metadata, lazy); `GRANT | REVOKE SOURCE` at the
   alias and schema level; a catalog admin builds only over granted sources (`source_not_granted`).

## Design

### 0. Two deployments (owner, 2026-10-10)
- **Standalone node** (the open duckdb-acl): configured by its bootstrap SQL and its admin's `ACL NATIVE`;
  secrets local (duckdb's secret manager) or in tresor, by choice; no cluster profile, no drift, no
  `cluster` bundle; `ACL CLUSTER …` is refused there with a clear message.
- **Cluster node** (the platform - BUSL, with the orchestrator): tresor required, the profile is how
  the fleet is configured, drift (§3), `operate` + `cluster`.
- The mode is a deployment setting `acl_deployment = 'standalone' | 'cluster'` (GLOBAL-only, set at
  start by the operator, never by the policy or the profile; default `standalone`).
- The cluster parts (profile, drift, the `cluster` bundle) are kept in their own files behind one seam
  the core calls: before the release they move to **hugr_node**, where duckdb-acl is a submodule.

### 1. Bundles (spec 117's model)
- `operate` = `observe` + sessions (kill, audit level, profile), drain / resume, node load.
- `cluster` = `operate` + the cluster profile (`ACL CLUSTER …`: extensions, ATTACH / DETACH by secret
  name, settings, groups), drift, the physical tree's metadata (`platform.attached.*`). **No data** of
  physical sources and no `ACL NATIVE`.
- `passthrough` ⊇ all. `policy` has none of them. 117's interim passthrough-only items move here
  (session profile → `operate`; cluster_items, cluster_effective → `cluster`).
- What `cluster` may `ACL CLUSTER SET` excludes the settings that are a data path (`http_proxy*`,
  `ca_cert_file`, log paths and targets, `custom_user_agent`, …) - those stay `passthrough`'s. This is
  the bundle's boundary on the profile grammar, not a restriction of `ACL NATIVE`.

### 2. `ACL NATIVE` is the break-glass (owner, 2026-10-10)
- Under `passthrough`, `ACL NATIVE <sql>` runs as written - ATTACH, INSTALL, SET GLOBAL, secrets,
  `query()` included; no statement list, no scope trap, no forced storage. Every analogue does the same:
  the superuser can do everything, access to it is what is fenced (here: passthrough only, reached only
  through a client's own mapping - spec 095).
- It stays visible: every statement is an audit event with its principal; in cluster mode drift (§3)
  lists what a node carries outside its profile.
- A change for the whole cluster or a group is `ACL CLUSTER … [IN GROUP g]` (spec 093/096) - `cluster`
  or `passthrough`.

### 2a. Secrets (owner, 2026-10-10)
- With a secrets service attached: unchanged - `CREATE [PERSISTENT] SECRET` / `DROP SECRET` under a
  principal holding `secrets` is a write to the service (spec 082).
- **Standalone without a service**: under a principal holding `secrets`, duckdb's own rule - `CREATE
  PERSISTENT SECRET` goes to the node's persistent storage (files), `CREATE SECRET` without a persistence
  keyword to memory (lost at restart). `TEMPORARY` / `TRANSACTION` stay refused under a service (082).
  The docs say plainly that a persistent local secret is a file on the node's disk.
- Under `ACL NATIVE`: duckdb as is (§2).
- tresor **variables** and `corp.*` management calls are the service's (its admin check, the function
  gate); unchanged here.

### 3. Drift (cluster mode)
`platform.drift` (an `acl_platform_drift()` table function, `cluster`): per kind (database, extension,
setting) what this node carries that its group's effective profile lacks, and what the profile names
that the node lacks or carries differently (path, version, value). Bootstrap is listed once as
`bootstrap`, never compared: system / temp / internal databases, the default memory database, the
policy catalog's database, the secrets service catalog(s), statically linked extensions, deployment
settings (`acl_deployment`, `acl_node_group`, `acl_jwks_locations`, …). Showing only - the node never
reverts anything itself.

### 4. Node operations as grammar
`KILL SESSION '<id>'`, `SET SESSION '<id>' AUDIT LEVEL <level>` (a quoted id: spec 068's
`SET SESSION TimeZone = …` is never captured, markerless included), `PROFILE SESSION …` (exists),
`DRAIN NODE`, `RESUME NODE` - compiled into the existing `acl_*` calls under `operate`;
`MIGRATE POLICY CATALOG <db>[.<schema>]` under **passthrough** (it moves the schema window of every
node). Typed views of 117 (`sessions`, `node_load`, `drain`) show the result.

### 4a. `platform.audit_events` (observe)
The node's audit ring (`acl_audit_events()`) as a typed view - what a console shows for "what just
happened here"; history beyond the ring is acl-otel's. One registry entry.

### 5. The physical tree: `platform.attached.<alias>.<schema>.<object>` (118.3)
Metadata only: databases, schemas, tables, views (no view SQL, no column defaults - text that can carry
data), columns with types, comments. Answered by a C++ `acl_platform_attached(alias[, schema])` that
reads ONE attached catalog's schema set (never duckdb_tables / duckdb_columns, which scan every
database) - a tree node loads its children only (design/079 principle 5).
- Scope: `cluster` / `policy` / `passthrough` - every attached database except the policy catalog's and
  the secrets service; a catalog admin - only what `GRANT SOURCE` gives it (§5a).
- Cost (measured in research): postgres loads its whole remote catalog on the first touch of any
  schema (cached until `pg_clear_cache`; narrowed only by ATTACH's `SCHEMA` option), mysql is lazy per
  schema, ducklake in memory, mssql to be measured. 119's row limit applies.

### 5a. Source grants (owner, 2026-10-10)
`GRANT SOURCE <alias>[.<schema>] TO ROLE r` / `REVOKE SOURCE … FROM ROLE r` - a grant on a node of
`platform.attached`, stored in `platform_grants` (kind `source`), written by `policy` or `passthrough`
(a delegation of data: the catalog admin reads it through its catalog; `cluster` attaches sources but
hands out no data). The object level is added later, if needed (Databricks' external location is a
prefix too).
- It gives: the subtree in `platform.attached` (metadata), and the right to reference those physical
  objects in definitions - `relations.phys`, `schemas.phys_path` (alias / expansion), a function's
  target, the tables a view body reads. A reference outside the granted sources is refused at write.
- `passthrough`, `policy`, `cluster` see every source without a grant.
- **Existing state** (owner, 2026-10-10): objects declared before the rule keep working - nothing is
  taken back automatically; `acl_check_catalog` reports each as `source_not_granted` with the
  `GRANT SOURCE …` (or the DROP) to run; only an explicit command removes.

### 6. DETACH and views (118.1)
The cluster DETACH check (spec 093: CASCADE / FORCE) also counts a virtual view whose body names the
source as a qualifier (`src.` / `"src".`, read as text - never bound, which would load the source's
catalog; over-reading blocks, FORCE is the operator's answer). Who reads what per role (`exposures`) is spec 120's, with
`effective_rights`.

## Enforcement & security

- No bundle below passthrough reads physical data; `cluster` sees names, types and comments only.
- `ACL NATIVE` is unchanged: passthrough's, audited, unrestricted.
- Data-path settings are not `cluster`'s to set through the profile.
- `MIGRATE POLICY CATALOG` stays passthrough.
- New bundles are privileged roles (spec 095): reached only through a client's own mapping.

## Testing

- `test/sql/node_operate.test`: KILL / SET AUDIT LEVEL / PROFILE / DRAIN / RESUME as grammar and as
  `platform.*` calls under `operate`; refused under `observe` and `policy`; MIGRATE refused under
  `operate` / `cluster`; `audit_events` under `observe`.
- `test/sql/node_secrets_local.test`: standalone without a service - PERSISTENT to files, bare to memory,
  `secrets` required; with a service - 082 unchanged.
- `test/sql/cluster_detach_view.test`: a view over a source blocks its DETACH; CASCADE / FORCE.
- `test/sql/node_drift.test` (cluster mode): an `ACL NATIVE` ATTACH / extension / GLOBAL setting outside
  the profile works and is listed; a profile item missing listed; bootstrap entries labelled; standalone
  has no drift and refuses `ACL CLUSTER`.
- `test/sql/platform_attached.test`: the tree per scope (a catalog admin - granted sources only), no view
  SQL / defaults, lazy per alias / schema; `GRANT SOURCE` checked at write; an older object keeps
  working and is a `source_not_granted` finding; postgres under integration.
- Door / Flight e2e: an `operate` token drains and resumes; a `cluster` token attaches through the
  profile and cannot `ACL NATIVE SELECT` a physical row.

## Alternatives considered

- **Configuration only through the profile, refused even under `ACL NATIVE`** (design/079, 2026-10-09) -
  dropped by the owner 2026-10-10: a statement list with a SET-scope trap, function names and a
  best-effort `query()` never closes; no analogue restricts its break-glass. Drift shows instead.
- Forcing a NATIVE `CREATE SECRET` into tresor - dropped with it.
- One `cluster` role with data (passthrough) - the platform engineer then reads every source.
- `GRANT SOURCE` per object from the start - alias / schema first.
- `exposures` here - moved to 120 with `effective_rights` (the same dependency map).

## Follow-ups

- 119: metadata row limit (one GLOBAL `acl_metadata_max_rows`, a session may lower it, a refusal never a
  truncation), RPC batching, filter pushdown + benchmark, quack load limit; a timeout only if the
  benchmark asks for one.
- 120: `view_as` as a session mode (a second connection "metadata as role r", minimal first), effective
  rights, `exposures`, ddl / export, the missing ALTER / REVOKE.

## As built

### 118.1 (2026-10-10)
- `operate`: `AdminScope::OPERATE` / `AdminRights::operate` (an `admins` row `operate`, global only - scoped to
  a catalog it grants nothing, like observe; passthrough implies it; it carries observe, so `REVOKE ADMIN
  observe` from an operate holder is refused). No schema step: the scope column is text, and a build
  before 118 reads `operate` as an unknown scope (grants nothing, the role stays privileged - spec 097).
  `PlatformRight::OPERATE` = the bundle, or a point grant on the function (the point grant is no longer
  refused for OPERATE).
- Functions: `kill_session` (acl_session_kill), `session_audit_level`, `session_profile`, `drain`, `resume`
  (OPERATE); `migrate_catalog` (ESCALATES, its own message). Grammar `KILL SESSION`, `SET SESSION '<id>'
  AUDIT LEVEL <level>|DEFAULT`, `DRAIN NODE`, `RESUME NODE`, `MIGRATE POLICY CATALOG` - recognized markerless
  (`IsMgmtStart`); `SET SESSION` only before a single-quoted id.
- `platform.audit_events` (NODE class): the ring's decision columns (no profile numbers).
- Secrets: `LocalSecrets` - no service attached and no storage named → duckdb's own handling (TEMPORARY too,
  memory); capability and constants unchanged; GRANT / REVOKE SECRET and identity `FROM SECRET` still need a
  service. 118.2's cluster mode will refuse the local path.
- DETACH: `SqlNamesSource` over `relations.view_sql`.
- Tests: `node_operate.test`, `acl_secrets.test` (the local block; type `http` - the suite loads no httpfs),
  `acl_cluster_profile.test` (views; fails without the fix), `platform_views` / `platform_rights` /
  `acl_observe` / `acl_profile` updated.

