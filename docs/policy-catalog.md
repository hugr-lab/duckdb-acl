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
without a policy source, and a `KEYS FROM` issuer cannot read its document in memory mode
([authentication.md](authentication.md)).

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
- **By hand**: apply [`schema/acl_schema.sql`](../schema/acl_schema.sql) with your own tooling - the
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
[`schema/policy_schema.sql`](../schema/policy_schema.sql), the source of truth:

| table | holds |
| --- | --- |
| `meta` | `schema_version` (the shape of these tables) and `policy_version` (bumped on every write) |
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
| `function_gate` | per-role or global (`role = ''`) allow/deny rows over function names; the built-in denylist applies otherwise |
| `admins` | global administration scopes: `manage` or `passthrough`, optionally per catalog |
| `issuers` | JWT issuers: keys or `jwks_uri`, audiences, algs, role claim, claim map, `client_id`, `client_secret` |
| `role_mappings` | external value → role, per issuer and source (`group` / `claim-value`) |
| `references` / `reference_columns` | declared join paths between objects and the columns each end names (spec 022) |
| `keys` | a declared primary key per object - a hint, never enforced (spec 048) |

## Schema versions and migration (spec 034)

The catalog says which shape it is - `meta.schema_version`, currently **13** - and a build reads
exactly one shape. The check happens where the catalog is chosen, not in the middle of somebody's
query:

- `acl_use_db(db, schema, false)` on another version: *"acl catalog: "db"."schema" is schema
  version 9, this build reads 13 - apply the matching schema/acl_schema.sql, or let acl_use_db(...,
  true) create it"*.
- `acl_use_db(db, schema, true)` on an older stamp: *"... is schema version 9 and this build creates
  13 - an older catalog is migrated (schema/migrations/v<n>.sql for every version above 9, in order),
  not re-initialised"*. `CREATE TABLE IF NOT EXISTS` cannot add a column to a table that exists, so
  replaying the schema is not a migration.
- No stamp at all: *"... has no schema_version - it is not an acl policy schema, or it was applied
  without the version stamp (see schema/acl_schema.sql)"*. A stamp that is not a number: *"... has
  schema_version "ten", which is not a number"*; `init := true` repairs an unreadable stamp.

**The extension never applies migrations itself.** To bring an older catalog forward:

1. Read the stamp: `SELECT value FROM store.acl.meta WHERE key = 'schema_version'`.
2. Apply every `schema/migrations/v<n>.sql` with `<n>` above it, in order, against the database that
   holds the schema. Each step ends by stamping its own number, so a catalog at 12 runs only `v13`.
   Shipped steps: `v11.sql` (spec 048: `nullable` on the column tables, the `keys` table),
   `v12.sql` (spec 064: `client_id` / `client_secret` on `issuers`), `v13.sql` (drops the unused
   `schema_aliases` table).
3. Re-open with `acl_use_db(..., false)`.

The steps are written in duckdb dialect; on another engine translate them as you did the schema. A
*newer* stamp than the build reads means a newer build wrote it - upgrade the extension, do not
downgrade the catalog.

The contract behind this (`schema/migrations/README.md`): `acl_schema.sql` always creates the current
version complete, a fresh catalog never replays history, and a migrated catalog must be identical to
a fresh one. Developers keep it honest with two targets: `make schema` renders
`schema/policy_schema.sql` into the C++ header the extension runs and into `schema/acl_schema.sql`;
`make schema-check` fails when those are stale, applies the hand-file to an empty database and serves
a policy from it with init disabled, and builds a catalog from the schema `origin/main` ships, applies
every step above its version, and diffs every `acl` table's column shape against a fresh catalog.

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
  "function_gate":    "my_function_gate",    -- optional
  "role_claims":      "my_role_claims",      -- optional
  "issuer":           "my_issuer",           -- optional
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
| `function_gate` | `(roles, names)` | `(role, name, kind, allowed)`, `''` role = global; absent = built-in denylist |
| `role_claims` | `(roles)` | `(role, claim, value)`; absent = no role-default claims |
| `issuer` | `(iss)` | `(issuer, keys_json, audiences, algs, role_claim, claim_map[, jwks_uri[, client_id, client_secret]])`; absent = no JWT issuers |
| `role_mappings` | `(issuer, external_values)` | `(external_value, role)`; absent = no external mapping - an unmapped value counts as a role iff `role_catalogs([value])` grants it something |
| `admin_scopes` | `(roles)` | `(role, scope, vcat)`; absent = no global admin scopes |

What the driver does *not* have: a schema level (no schema grants, no `create`/`drop` homes), any
write path (*"acl catalog: the function-driver policy source is read-only"* on every admin write),
and enumeration - the introspection listings refuse (*"this policy source does not expose
enumeration ..."*), `acl_status()` reports `enumerates = false` with no versions, and the doors'
auth discovery lists no issuers, so the Flight password handshake finds no `CLIENT ID` to run as.
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
`acl_issuers()`, `acl_role_mappings()`, `acl_function_gate()`, and `acl_status()`.

The column names and types come from the storage at bind, so a listing cannot drift from the tables;
the rows are read per execution, so a prepared statement shows the policy as it is now. Two
deliberate omissions: `acl_issuers()` has no `keys_json` (an HS256 key is a shared secret, not
metadata) and no `client_secret`. Without a source the listings refuse rather than answer nothing -
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

What is **not** in the catalog, and does not travel with it: sessions (per node, in memory), the JWKS
cache and the OIDC discovery cache (per node / per process), the settings (`SET GLOBAL` per node -
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
  node independently; a `kid` a node has not seen triggers its own re-read.
- Settings are per node; set them identically, or accept that a node with `every_use` and another
  with `connect` judge the same session differently.
- A read-only replica of the catalog database serves a node that never writes; administration goes
  to a node attached to the primary.

## Not verified

- Behaviour when two nodes write the catalog concurrently: each write is one transaction ending in
  the version bump, and nothing beyond the database's own isolation orders them.
- Whether the mssql scanner honours `CREATE TABLE IF NOT EXISTS` on a *current* catalog re-init; the
  extension judges the stamp before running any DDL, which is what makes re-running it safe.
