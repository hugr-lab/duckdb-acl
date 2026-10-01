# The policy catalog: where policy lives and how it is operated

A node reads its policy - virtual catalogs, roles, grants, issuers, mappings - from exactly one
**policy source**. Three exist; the last one enabled wins and is the exclusive source for every
resolver:

| source | enabled by | writable | enumerable | for |
| --- | --- | --- | --- | --- |
| memory | nothing (the default) | yes, in process memory | no | dev and tests; the `acl_grant_*` / `acl_define_token` stubs |
| catalog | `acl_use_db(db [, schema [, init]])` | yes, through the admin functions and `ACL ADMIN` | yes | production: tables in any ATTACHed database (spec 006) |
| function driver | `acl_use_functions('{"slot": "fn", ...}')` | no | no | a platform that serves its catalog through registered table functions (spec 008) |

`acl_status()` says which is active: `backend` (`memory` / `catalog` / `functions`),
`schema_version`, `policy_version`, `version_check_interval`, `enumerates`. Both doors refuse to serve
without a policy source ([authentication.md](authentication.md)).

Both enablers refuse while enforcement is off: *"acl: allow_parser_override_extension is DEFAULT, so
no `ACL …` statement is parsed and nothing is enforced - SET GLOBAL
allow_parser_override_extension='STRICT' before ..."*. The extension sets `STRICT` on load unless an
explicit value was set before it.

## Choosing the catalog database

Any database duckdb can ATTACH will do - a duckdb file, PostgreSQL through `postgres_scanner`, SQL
Server through the mssql scanner (spec 033), DuckLake. The extension speaks **standard duckdb dialect
only** and never depends on the source: reads run on short-lived connections on the same instance,
with literal predicates the scanners push down; writes run as `BEGIN; ...; UPDATE meta; COMMIT` on a
short-lived connection, with portable `DELETE`+`INSERT` upserts.

```sql
ATTACH 'policy.duckdb' AS store;                                   -- a file
ATTACH 'dbname=aclmeta host=... user=...' AS store (TYPE postgres); -- or a scanner
SELECT acl_use_db('store');                 -- schema 'acl', must already exist
SELECT acl_use_db('store', 'security');     -- another schema name
SELECT acl_use_db('store', 'acl', true);    -- init: create the schema if it is absent
```

Two ways to get the schema there:

- **`init := true`** creates every table (`CREATE TABLE IF NOT EXISTS`, one statement each) and
  stamps the version. Re-running it on a current catalog is cheap and changes nothing. It refuses a
  catalog stamped with an older version (below) rather than replaying DDL over it.
- **By hand**: apply [`schema/acl_schema.sql`](https://github.com/hugr-lab/duckdb-acl/blob/main/schema/acl_schema.sql) with your own tooling - the
  duckdb-dialect rendering, ready to run, creating schema `acl` in the database it runs against -
  and then `acl_use_db('store', 'acl', false)`. This is how the catalog lives in a database the node
  is not allowed to create tables in, under somebody else's migration tooling and grants. Whoever
  applies it owns the grants on those tables; a node that only reads needs only `SELECT`, and admin
  writes from such a node fail with *"acl catalog: write failed: ..."*.

For another engine, translate the file (the SQL is plain; sqlglot and friends handle it). Two things a
target may need changing, both from the SQL Server experience (spec 033):

- **Key columns are indexed**, so they need a bounded type where the engine cannot index an unbounded
  one. The source file marks them `ACL_KEY_TEXT`; the extension substitutes `VARCHAR` everywhere but
  on an `mssql` catalog, where it uses the scanner's `MSSQL_VARCHAR(255)`. On SQL Server, 255
  characters is therefore a real limit on a catalog name, an object name, a role, a schema path or an
  issuer.
- `IF NOT EXISTS` on `CREATE TABLE` / `ADD COLUMN` is not universal - T-SQL guards instead.

The stored boolean columns are always compared (`= true`), never asserted bare, so engines without a
boolean type work.

## The tables at a glance

Every table carries a primary key (sources without rowids need one for `DELETE`/`UPDATE`); `''`
stands in for "global" / "any" wherever NULL cannot be part of a key. `caps` columns hold a flat JSON
object of booleans (`{"select": true, "manage": true}`), extensible without a migration. From
[`schema/policy_schema.sql`](https://github.com/hugr-lab/duckdb-acl/blob/main/schema/policy_schema.sql), the source of truth:

| table | holds |
| --- | --- |
| `meta` | `schema_version` (the shape of these tables), `min_reader_version` (the oldest build that may read it, spec 094), `policy_version` (bumped on every policy write) and `config_version` (on every cluster profile write, spec 093) |
| `catalogs` | the virtual catalogs and their comments |
| `relations` | virtual tables and views: `form` (`alias` / `subquery` / `view`), physical target, view SQL, inline RLS, origin, whether the RLS was checked |
| `relation_columns` | an object's own projection: position, name, expression, nullability |
| `object_columns` | the declared or derived column schema (name, type, comment, nullable) of every object, keyed by kind - what `DESCRIBE` and the listings answer with (spec 010) |
| `functions` | virtual table functions and scalars: kind, `form` (`alias` / `macro`), target, template, params |
| `schemas` | virtual schemas: path, physical path (an alias) or none, origin (an expansion), comment |
| `schema_dropped` | records dropped on purpose from an expanded schema, so a `REFRESH` does not bring them back |
| `roles` | the roles and their comments |
| `role_claims` | a role's default claims (`role, claim, value`) |
| `role_catalogs` | catalog grants: `is_main`, caps, RLS, column list, `rls_checked` |
| `role_schemas` | schema grants: caps, whether inherited, `into` (the physical home for `create`), `virtual_only` |
| `role_object_caps` | object grants: caps, RLS, column list |
| `grant_columns` | the columns a grant's projection produces (a mask that changes a type, a computed column) - spec 026 |
| `function_categories` | the function categories (spec 072): name, comment, `builtin` (seeded at creation - never touched by the extension again) |
| `function_category_members` | a category's keys: `database, schema, name, kind` (`scalar` / `table`) |
| `function_grants` | per-role or every role's (`role = ''`) grants and denies on a category (key columns `''`) or on a function by name (category `''`); a deny anywhere wins |
| `resource_groups` | spec 085: a group's limits (`window_start`, `window_max`, `batch_bytes`, `max_result_rows`, `queue_priority`, `max_sessions`; NULL = the node's setting) and comment |
| `role_resource_groups` | which roles are in which groups |
| `admins` | global administration scopes: `manage` or `passthrough`, optionally per catalog |
| `issuers` | JWT issuers (spec 095): name, URL, and the name of an `oidc_issuer` secret with its service - never a key |
| `clients` | which tokens of an issuer count and what they become: audiences, azp, requires, roles from/constant, unmapped, attributes, subject, token type, client id, flows, an `oidc_client` secret's name, implicit - never a credential |
| `role_mappings` | external value → role, scoped to a client or an issuer (`scope_kind`, `scope_name`), per source (`group` / `claim-value`) |
| `references` / `reference_columns` | declared join paths between objects and the columns each end names (spec 022) |
| `keys` | a declared primary key per object - a hint, never enforced (spec 048) |

## Schema versions and migration (specs 034, 094)

The catalog says which shape it is: `meta.schema_version`, currently **18**. It also says the oldest
build that may still read it: `meta.min_reader_version`, currently **17**. A build judges the pair
where the catalog is chosen (`acl_use_db`) and again at every freshness check (below), so a catalog
migrated under a running node is noticed without a restart.

| the catalog is | the node | message |
| --- | --- | --- |
| the build's version | serves and writes | - |
| newer, and `min_reader_version` ≤ the build | **serves, never writes** (read-only) | a write: *"… is schema version 17 and this node's build writes 16 - policy is written from a node of the catalog's build …"* |
| newer, outside that window | refuses every statement (fail closed) | *"… is schema version 17, readable from build 17 on, and this build is 16 - upgrade the node"* |
| older | refuses, and says what to do | *"… is schema version 15 and this build reads 16 - migrate it first: SELECT acl_migrate_catalog('store', 'acl') on a node of this build"* |

A catalog without a stamp is not an acl schema. A stamp that is not a number is refused, and
`init := true` repairs an unreadable one.

**Migrating: `acl_migrate_catalog(db[, schema])`.** A build carries its migration steps (from v11 on)
and applies every step above the catalog's version in **one transaction**, then answers what it did:
*"… migrated from schema version 15 to 16 (readable from build 15 on)"*.
- It is idempotent: *"… is already schema version 16"*.
- It refuses a newer catalog, because a catalog only moves forward.
- It refuses a catalog older than the build's first step: migrate with an older build first.
- Like every `acl_*` function it is denied to a principal. It is the operator's or the node agent's
  step, run on the node's own connection.

**A rolling upgrade across a schema change**, for a step that keeps older builds in its window:

1. Run `acl_migrate_catalog` from one node or job of the new build. The old nodes keep serving from the
   migrated catalog, and they refuse policy writes.
2. Roll the nodes to the new build.
3. Write policy again. Every node is now of the catalog's build.

A step that cannot keep older builds reading (`min_reader` equal to its own version) turns the old
nodes off at their next freshness check. That upgrade is a switch-over, not a rolling one.

**The window is declared, never assumed.** Each step in `schema/migrations/` states
`-- min_reader: <n>` in its header. Only its author knows whether an older build that ignores what the
step adds can ever admit more. A new column that *narrows* access, read by the new build only, would
widen access on an old node that ignores it, so such a step must declare its own version. v16 only
adds the cluster profile's tables, so it keeps v15 readers, and v18 only marks a default resource group,
so it keeps v17 readers (a v17 build has no placement to widen). Every other step is strict - v17
rebuilds the identity tables.

The steps are also kept as files (`schema/migrations/v<n>.sql`, duckdb dialect) for applying by hand on
another engine. The shipped steps are:

| step | spec | what it does |
| --- | --- | --- |
| `v11` | 048 | adds `nullable` to the column tables and adds `keys` |
| `v12` | 064 | adds `client_id` and `client_secret` to `issuers` |
| `v13` | - | drops the unused `schema_aliases` table |
| `v14` | 072 | adds the function categories, seeded |
| `v15` | 085 | adds the resource groups |
| `v16` | 093 | adds the cluster profile; stamps `min_reader_version` 15 |
| `v17` | 095 | rebuilds `issuers` (name, URL, secret), adds `clients`, scopes `role_mappings`; each issuer becomes the short form (an issuer named by its URL and its implicit client); keys, algs, `jwks_uri` and `client_secret` are **dropped** - an issuer that relied on them needs an `oidc_issuer` / `oidc_client` secret or reads its keys by discovery; an audience `*` no longer means "any" |
| `v18` | 096 | adds `is_default` to `resource_groups` (the default group); keeps `min_reader_version` 17 |

The contract behind this is in `schema/migrations/README.md`:
- `acl_schema.sql` always creates the current version complete, and a migrated catalog must be
  identical to a fresh one.
- `make schema` renders `schema/policy_schema.sql` into the C++ header (with the steps embedded) and
  into `schema/acl_schema.sql`.
- `make schema-check` builds a catalog from the schema `origin/main` ships, applies every step above
  it, and diffs every `acl` table's column shape against a fresh catalog.

## Staleness: `policy_version` and `acl_version_check_interval`

Every admin write - an `ACL ADMIN` statement, an `acl_*` admin function - runs in one transaction that
ends with `UPDATE meta SET value = value + 1 WHERE key = 'policy_version'`. Each node keeps result
caches (resolved objects and functions, gate verdicts, role claims, issuers, admin rights) keyed by
that version and the principal's sorted role set, and re-reads the version at most once per
`acl_version_check_interval` milliseconds (GLOBAL, default `1000`; `0` = check on every batch). A
changed version clears every cache at once; the node that wrote forces a re-read on its own next
resolve. So a policy change is visible on the writing node immediately and on every other node within
the interval - nothing needs restarting. A `policy_version` source that answers other than one row is
refused (*"acl catalog: the policy_version source returned N rows, expected 1"*).

Rights are resolved per statement against the store; only identity is cached in a session handle
([authentication.md](authentication.md)), so a revoked grant bites at the next statement.

## The function-driver source (spec 008)

For a platform whose catalog lives behind C-API table functions - which never receive filter
pushdown, so a table-shaped source would materialise everything on each miss - the callback arguments
*are* the pushdown:

```sql
SELECT acl_use_functions('{
  "policy_version":   "my_policy_version",
  "role_catalogs":    "my_role_catalogs",
  "relations":        "my_relations",
  "relation_columns": "my_relation_columns",
  "schema_aliases":   "my_schema_aliases",
  "functions":        "my_functions",
  "object_caps":      "my_object_caps",      -- optional
  "function_categories":       "my_function_categories",  -- optional, the three together (spec 072)
  "function_category_members": "my_function_members",
  "function_grants":           "my_function_grants",
  "role_claims":      "my_role_claims",      -- optional
  "issuers":          "my_issuers",          -- optional, spec 095
  "clients":          "my_clients",          -- optional, spec 095
  "role_mappings":    "my_role_mappings",    -- optional
  "admin_scopes":     "my_admin_scopes"      -- optional
}');
```

The map is explicit - no autodetection. Enabling fails closed: the six core slots are required
(*"acl_use_functions: required slot "role_catalogs" is missing"*), every named function must exist
in `duckdb_functions()` (*"slot "x" names an unknown function "y""*), and the `policy_version`
callback is probed before the switch. The contract, positional (extra columns are ignored; list
arguments arrive as `VARCHAR[]` literals):

| slot | called as | must return |
| --- | --- | --- |
| `policy_version` | `()` | one row: `(version BIGINT)` |
| `role_catalogs` | `(roles)` | `(role, vcat, is_main, caps)` |
| `relations` | `(catalogs, names)` | `(vcat, vname, form, phys, view_sql, rls)` |
| `relation_columns` | `(catalogs, names)` | `(vcat, vname, pos, name, expr)` |
| `schema_aliases` | `(catalogs)` | `(vcat, alias_path, phys_path)` |
| `functions` | `(catalogs, names)` | `(vcat, vname, kind, form, target, template)` |
| `object_caps` | `(roles, catalogs, names)` | `(role, vcat, vname, caps)`; absent = catalog-default caps only |
| `function_categories` | `()` | `(category, comment, builtin)` - spec 072: the three category slots are declared together or not at all; absent = the shipped categories decide |
| `function_category_members` | `()` | `(category, database, schema, name, kind)` |
| `function_grants` | `()` | `(role, category, database, schema, name, kind, allowed)`, `''` role = every role |
| `role_claims` | `(roles)` | `(role, claim, value)`; absent = no role-default claims |
| `issuers` | `()` | `(name, url, secret_service, secret)`; absent = no JWT issuers (spec 095) |
| `clients` | `()` | the `clients` table's columns in order (`name, issuer, audiences, azp, requires, roles_from, roles_constant, unmapped, attributes, subject, token_type, client_id, flows, secret_service, secret, implicit`; lists as JSON arrays); absent = no clients, so no token verifies |
| `role_mappings` | `()` | `(scope_kind, scope_name, source, external_value, role)`; absent = no mappings - an unmapped value counts as a role (for a client with `UNMAPPED AS ROLE`) iff `role_catalogs([value])` grants it something |
| `admin_scopes` | `(roles)` | `(role, scope, vcat)`; absent = no global admin scopes |

What the driver does *not* have: a schema level (no schema grants, no `create`/`drop` homes), any
write path (*"acl catalog: the function-driver policy source is read-only"* on every admin write),
and enumeration - the introspection listings refuse (*"this policy source does not expose
enumeration ..."*), `acl_status()` reports `enumerates = false` with no versions, and the doors'
auth discovery lists what the `issuers` and `clients` slots answer (nothing without them).
Staleness and caches are the catalog's (`acl_version_check_interval` applies to the
`policy_version` callback). `test/sql/acl_functions_driver.test` mocks the whole contract with
`CREATE MACRO ... AS TABLE` over `VALUES`, which is the quickest way to see the shapes in use.

## Introspection for operators

One table function per listing, readable in the native context (every `acl_*` name is denied inside
a principal's query - *"table function "acl_issuers" is not allowed"*): `acl_catalogs()`,
`acl_schemas()`, `acl_relations()`, `acl_relation_columns()`, `acl_object_columns()`,
`acl_functions()`, `acl_references()`, `acl_reference_columns()`, `acl_roles()`, `acl_role_claims()`,
`acl_grants()` (from `role_catalogs`), `acl_schema_grants()` (from `role_schemas`),
`acl_object_grants()` (from `role_object_caps`), `acl_grant_columns()`, `acl_admins()`,
`acl_issuers()`, `acl_clients()`, `acl_role_mappings()`, `acl_function_categories()`, `acl_function_category_members()`,
`acl_function_grants()`, and `acl_status()` - plus `acl_function_status([role])`, which joins the
node's own `duckdb_functions()` with the categories (spec 072): every function with its categories
and status (`never` / `categorized` / `uncategorized`), and with a role, whether it may call it and
what decided. The three category listings answer in every mode, the seed included.

The column names and types come from the storage at bind, so a listing cannot drift from the tables;
the rows are read per execution, so a prepared statement shows the policy as it is now. No key and no
credential is in them to begin with: an issuer's keys and a client's secret live in the secrets
service (spec 095), and the listings show the secret's name. Without a source the listings refuse rather than answer nothing -
*"no policy source is active, so there is nothing to list - run acl_use_db() or acl_use_functions()
first"* - because on an admin surface silence reads as "nothing is configured"; `acl_status()` always
answers.

The session and node surfaces are separate and live in memory, not in the catalog: `acl_sessions()`,
`acl_session_count()`, `acl_session_kill(id)`, `acl_session_sweep()`, and the graceful stop
`acl_drain()` / `acl_drain_status()` / `acl_resume()` (spec 066).

## Backing up and moving a catalog

The catalog is ordinary tables in the database you chose, so its backup is that database's backup -
a duckdb file is copied or `EXPORT DATABASE`d, PostgreSQL is dumped. Keep the two `meta` rows: a
restored schema without `schema_version` is refused as not an acl schema, and `policy_version` is what
every node's cache is keyed on (a restore that *lowers* it still changes it, which clears the caches
- any change does).

To move a catalog, attach it under its new home and point the node at it with init disabled:
`acl_use_db('newstore', 'acl', false)`. The version check applies as on any open. The schema name is
whatever it was created as; `acl_schema.sql` renders `acl` and an operator wanting another name edits
the applied copy.

What is **not** in the catalog, and does not travel with it: sessions (per node, in memory), the
discovery/JWKS document cache and the doors' OIDC endpoint cache (per node / per process), the
issuers' and clients' secrets (the secrets service's), the settings (`SET GLOBAL` per node -
`acl_version_check_interval`, `acl_jwt_clock_skew`, the JWKS and session settings), and everything the
memory-mode stubs hold (`acl_define_token`, an issuer defined before `acl_use_db`).

## Several nodes on one catalog

Nodes are identical and share nothing but the catalog:

- Every node reads the same tables and polls `policy_version` on its own interval, so a write from
  any node - or from your own tooling, as long as it bumps `policy_version` - reaches the fleet within
  `acl_version_check_interval`.
- Sessions are per node: a client's session exists only on the node that opened it, so a front that
  routes must keep a client on one node (the Flight door's session cookie, quack's per-connection
  binding). There is no shared session backend, by decision.
- Issuer keys are re-read per node (`acl_jwks_refresh_interval`), so an IdP rotation reaches each
  node independently; a `kid` a node has not seen triggers its own re-read. A secret's change reaches
  each node at its next read through the service's cache, with no policy write.
- Settings are per node; set them identically, or accept that a node with `every_use` and another
  with `connect` judge the same session differently.
- A read-only replica of the catalog database serves a node that never writes; administration goes
  to a node attached to the primary.

## Not verified

- Behaviour when two nodes write the catalog concurrently: each write is one transaction ending in
  the version bump, and nothing beyond the database's own isolation orders them.
- Whether the mssql scanner honours `CREATE TABLE IF NOT EXISTS` on a *current* catalog re-init; the
  extension judges the stamp before running any DDL, which is what makes re-running it safe.
