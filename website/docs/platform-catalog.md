# The platform catalog

`platform` is a system virtual catalog (spec 117) that answers an administrator's questions and takes
their changes **without `ACL NATIVE`**: **views** over the policy and the node, with typed columns and
rows scoped to the caller, and **management functions** `platform.<op>(…)` called at the top level of a
statement. Who may read or call what is a grant on `platform`'s own objects - a built-in bundle, or a
point grant on one view or function - so the tree a database tool shows under `platform` is exactly what
that administrator may use.

```sql
-- an administrator through any door or gateway prefix - no ACL NATIVE, no ACL marker
SELECT role, catalog, caps."select", columns FROM platform.grants WHERE catalog = 'sales';
SELECT * FROM platform.sessions;
SELECT platform.grant_catalog('analyst', 'sales', caps := ['select'], main := true);
GRANT CATALOG sales TO ROLE analyst WITH (select) MAIN;   -- the same operation, in the grammar
```

## What it is

- **Synthesized, never stored.** Nothing of `platform` lives in the policy catalog; its views are SQL
  over the policy catalog's tables (or, for the node's state, internal table functions), substituted
  for the principal before the function gate, like the metadata surfaces.
- **The name is reserved.** `CREATE VIRTUAL CATALOG platform` (any spelling, `"Platform"` included),
  every management call that names a catalog (`ADD TABLE … AS platform.x`, `GRANT CATALOG platform …`,
  `acl_create_catalog('platform')`, `CHECK VIRTUAL CATALOG platform`, …), a function-driver source whose
  `role_catalogs` answers it, and a function category or function grant naming `platform.<f>` are all
  refused. `USE platform` is refused too: a session's default catalog is a data catalog - name the
  objects as `platform.<view>`.
- **Where it appears.** In `information_schema.*`, `duckdb_databases()` / `duckdb_schemas()` /
  `duckdb_views()` / `duckdb_columns()` / `duckdb_functions()`, `SHOW` and the Flight catalog RPCs - for a
  principal holding at least one grant on it, and only the objects it holds. One schema, `main`; a view
  is listed as `VIEW` with its description as the comment, a function in `duckdb_functions()` and
  `acl_function_columns()`. It is present under the gateway's `ACL ROLE` / `ACL TOKEN` prefixes and on
  the Flight door, and **absent on the quack door** (quack loads a catalog whole at `ATTACH`; the console
  is Flight / JDBC). A quack admin manages with the grammar.
- **Names.** `platform.<x>` and `platform.main.<x>` are the same object, compared case-insensitively.
  The views are read-only: `INSERT` / `UPDATE` / `DELETE` / DDL on them is refused.

In DBeaver (or any JDBC / ADBC tool over the Flight door) an administrator sees `platform` as one more
catalog in the tree: the views under *Views* (with their column types and comments) and the functions
under *Functions*. A role without administration does not see it at all.

## Who may read and call what

### Bundles

Built-in, fixed sets of `platform`'s objects, held as a **set** - a role may hold several, and no bundle
is "stronger" than another:

| Bundle | Granted with | Reads | Calls |
| --- | --- | --- | --- |
| `observe` | `GRANT ADMIN observe TO ROLE r` | the node views (`sessions`, `node_load`, `node_doors`, `node_streams`, `drain`, `lineage_status`, `audit_events`); also the load report and `/metrics` (spec 097) | nothing |
| `operate` (spec 118) | `GRANT ADMIN operate TO ROLE r` | `observe` | the node's runtime: `kill_session`, `session_audit_level`, `session_profile`, `drain`, `resume` - and their grammar (`KILL SESSION`, `SET SESSION … AUDIT LEVEL`, `PROFILE SESSION`, `DRAIN NODE`, `RESUME NODE`) |
| `cluster` (spec 118, a cluster node's) | `GRANT ADMIN cluster TO ROLE r` | `operate` + the cluster profile's views (`cluster_items`, `cluster_effective`, `drift`) | `operate` + the cluster profile (`cluster_extension`, `cluster_attach`, `cluster_detach`, `cluster_setting` - not a data-path setting); never `ACL NATIVE`, never a source's data |
| `policy` | `GRANT ADMIN policy TO ROLE r` | every policy view, all rows - not the cluster profile's | every policy function except the admin grants, the cluster profile and the node's runtime (`operate`'s) |
| `passthrough` | `GRANT ADMIN passthrough TO ROLE r` | everything | everything, plus `ACL NATIVE`, the bundles and the grants on `platform` (the break-glass) |
| `manage` (spec 009's name) | `GRANT ADMIN manage TO ROLE r` | `policy` + `observe` | `policy` |
| a catalog admin | `GRANT CATALOG c TO ROLE r CAPS '{"manage": true}'` | the catalog-scoped views, narrowed to its catalogs (below) | the functions that take a catalog, on its catalogs; `check_catalog` on its catalogs |

`REVOKE ADMIN <bundle> FROM ROLE r` takes one bundle (not one another carries: `observe` from a role holding
`operate`, `manage` or `passthrough` is refused - revoke the carrier); `REVOKE ADMIN FROM ROLE r` takes every bundle,
the `manage` capability of its catalog grants and its point grants on `platform`. Functions:
`acl_grant_admin(role, scope)`, `acl_revoke_admin(role[, scope])`.

A catalog admin keeps spec 009's limits: it may edit its catalogs' content but not hand out access
(`grant_catalog`, `grant_object`, `grant_schema`, `alter_grant`, `drop_catalog` need `policy`), and not
run what belongs to no catalog (roles, issuers, categories, resource groups).

### Point grants

One view or one function of `platform`, granted (or denied) to one role:

```sql
GRANT VIEW platform.sessions TO ROLE support;          -- support reads the sessions, nothing else
GRANT FUNCTION platform.create_role TO ROLE onboarding; -- may create roles: the call and CREATE ROLE alike
DENY VIEW platform.issuers TO ROLE pol;                 -- a deny wins over every bundle but passthrough
REVOKE VIEW platform.sessions FROM ROLE support;        -- the grant or the deny goes
-- functions: acl_grant_platform(role, 'view' | 'function', object[, allowed]),
--            acl_revoke_platform(role, kind, object)
```

- A view granted by name is read **whole** (all rows); a function granted by name may be called for any
  catalog.
- **Only `passthrough` grants on `platform`** (and the bundles) - never `policy`: a grantor that can
  grant everything is everything.
- Never to every role (`TO ALL ROLES` / role `''` is refused); never on `grant_admin`, `revoke_admin`, `grant_platform`, `revoke_platform`, `cluster_extension`, `cluster_attach`, `cluster_detach`, `cluster_setting`, `migrate_catalog` - the passthrough scope's own - and `console_info` (every holder's); only on an
  object `platform` has.
- The grants live in their own table, `platform_grants(role, object, kind, allowed)` - never in the
  catalog grants or spec 072's function grants and categories.
- A deny (`allowed = false`) anywhere among the principal's roles wins over a bundle; `passthrough` is
  never narrowed.

### What an administrator may store

A definition runs as the node when it is read, so what a non-`passthrough` administrator stores is
judged by **its own function gate** where it is written: every function a view, a macro template, an
alias target, an RLS, a column or mask expression (or a grant's policy) calls must be one the author
may call itself - its roles' categories and grants by name, a deny winning, the never set (`acl_*`,
`query*`, a scanner's `*_query`, ...) always refused; `acl_claim` / `acl_arg` are markers, not calls. A
body is a constant (never a `?`). No definition may name the policy catalog's own tables. Changing an
issuer or a client that carries a mapping to an administering role, mapping to such a role, and granting
a catalog's `manage` to a role a mapping reaches are `passthrough`'s. `REVOKE ADMIN <bundle>` of a
bundle the role does not hold - or holds only through `manage` / `passthrough` - is refused, naming
what to revoke.

### Rows per scope

| Scope | Rows |
| --- | --- |
| `policy`, `passthrough`, a point grant on the view | all |
| a catalog admin | its catalogs' objects, columns, schemas, functions, references, keys, the grants **on** its catalogs, and the **names** of the roles holding them (`roles` answers `role` with a NULL `comment`); no identity, categories, resource groups, cluster or node views |
| `observe`, `operate` | the node views only |
| none | the catalog is absent - not listed, `no access to object "platform.<x>"` |

### Privileged roles (spec 095, extended)

A role holding any bundle, any point grant on `platform` (grant or deny) or the `manage` capability on a
catalog is privileged: it is reached only through a client's own mapping (`MAP … FROM CLIENT c TO ROLE
r`) - never an issuer-wide mapping, `UNMAPPED AS ROLE` or `ROLES CONSTANT`. It is judged at use: a role
mapped issuer-wide before its grant stops counting at the next token.

## The views

Every column is typed - no packed JSON or csv. A capability set is `caps STRUCT("select" BOOLEAN,
"insert" BOOLEAN, "update" BOOLEAN, "delete" BOOLEAN, "merge" BOOLEAN, "create" BOOLEAN, "drop"
BOOLEAN, "temp" BOOLEAN, "explain" BOOLEAN, secrets BOOLEAN, manage BOOLEAN)` (NULL = unstated: on a
catalog grant every data capability, on an object grant inherited); a list is `VARCHAR[]`. The listing
of a view and `DESCRIBE platform.<view>` agree column for column.

Policy views (the `policy` bundle; marked *c* - also a catalog admin, narrowed):

| View | Columns |
| --- | --- |
| `catalogs` *c* | catalog, comment |
| `relations` *c* | catalog, name, form, phys, view_sql, rls, rls_checked BOOLEAN, origin, comment, alias_types, enum_types |
| `relation_columns` *c* | catalog, relation, pos BIGINT, name, expr, nullable BOOLEAN |
| `schemas` *c* | catalog, path, phys_path, origin, comment |
| `functions` *c* | catalog, name, kind, form, target, template, params VARCHAR[], comment |
| `function_columns` *c* | catalog, function, kind, pos BIGINT, name, type, comment, nullable BOOLEAN |
| `references` *c* | catalog, name, from_object, to_object, to_kind, expression, cardinality, optional BOOLEAN, join_method, comment |
| `reference_columns` *c* | catalog, reference, pos BIGINT, side, column, param |
| `keys` *c* | catalog, object, kind, pos BIGINT, column |
| `roles` *c* | role, comment |
| `role_claims` | role, claim, value |
| `grants` *c* | role, catalog, is_main BOOLEAN, caps, rls, rls_checked BOOLEAN, columns VARCHAR[] |
| `schema_grants` *c* | role, catalog, schema_path, caps, inherited BOOLEAN, into, virtual_only BOOLEAN, comment |
| `object_grants` *c* | role, catalog, object, caps, rls, rls_checked BOOLEAN, columns VARCHAR[] |
| `grant_columns` *c* | role, catalog, object, pos BIGINT, name, type |
| `admins` | role, scope, catalog (NULL = global) |
| `platform_grants` | role, object, kind, allowed BOOLEAN |
| `issuers` | name, url, secret_service, secret (a secret by its **name**, never its content) |
| `clients` | name, issuer, audiences VARCHAR[], azp VARCHAR[], requires `STRUCT(path VARCHAR, op VARCHAR, "values" VARCHAR[])[]`, roles_from VARCHAR[], roles_constant VARCHAR[], unmapped, attributes `STRUCT(name VARCHAR, paths VARCHAR[], constant VARCHAR)[]`, subject VARCHAR[], token_type, client_id, flows VARCHAR[], secret_service, secret, implicit BOOLEAN |
| `role_mappings` | scope_kind, scope_name, source, external_value, role |
| `jwks_cache` | issuer, location, allowed BOOLEAN, fetched_at TIMESTAMP, age_seconds BIGINT, last_tried_at TIMESTAMP, error, keys BIGINT, kids VARCHAR[] |
| `function_categories` | category, comment, builtin BOOLEAN |
| `function_category_members` | category, database, schema, name, kind |
| `function_grants` | role, category, database, schema, name, kind, allowed BOOLEAN |
| `function_status` | database, schema, name, kind, function_type, categories VARCHAR[], status, present BOOLEAN |
| `resource_groups` | group, window_start, window_max, batch_bytes, max_result_rows, queue_priority, max_sessions (BIGINT), comment, is_default BOOLEAN |
| `role_resource_groups` | role, group |
| `cluster_items` † | scope, kind, name, spec `MAP(VARCHAR, VARCHAR)`, class, version BIGINT, depends_on VARCHAR[], comment |
| `cluster_effective` † | the same, what applies to this node (spec 096) |
| `catalog_schema` | build, build_min_reader, catalog, min_reader (BIGINT), mode |

Node views (the `observe` bundle):

| View | Columns |
| --- | --- |
| `sessions` | id, subject, roles VARCHAR[], door, idle_seconds BIGINT, expires_at TIMESTAMP, audit_level, audit_level_source, profile_level, profile_source, groups VARCHAR[], charged_group - never a handle |
| `node_load` | draining BOOLEAN, observe, group, group_known BOOLEAN, config_target, config_applied, sessions_live, sessions_max (BIGINT), sessions_by_door `MAP(VARCHAR, BIGINT)`, sessions_by_group `MAP(VARCHAR, STRUCT(live BIGINT, max BIGINT))`, admit_new_session, admit_new_quack_client, admit_new_stream (BOOLEAN) - one row |
| `node_doors` | door, uri, seats, seated, seats_left (BIGINT) - one row per quack door |
| `node_streams` | budget_bytes, reserve_bytes, reserved_bytes, producing, queued, refused (BIGINT) |
| `drain` | draining BOOLEAN, sessions BIGINT |
| `lineage_status` | status, sending BOOLEAN, level, namespace |
| `audit_events` | ts TIMESTAMPTZ, seq BIGINT, kind, level, door, session, subject, issuer, roles VARCHAR[], statement, objects `STRUCT(name VARCHAR, capability VARCHAR)[]`, verdict, reason_code, reason, correlation_id, traceparent, rows, duration_us (BIGINT), detail - the node's recent events, its ring (spec 069); the history is the sinks' |

† the cluster profile's views are the `cluster` bundle's (spec 118; or a point grant's) - not the `policy`
bundle's: the policy admin has no cluster or node operations. `drift` (kind, name, state, node_value,
profile_value, scope) is this node against its profile; on a standalone node it is refused.

Unmarked columns are VARCHAR. The views that read the policy catalog's tables need a catalog policy
source (`acl_use_db`); in memory mode and behind a function driver they refuse with a clear error, while
the node views, `jwks_cache`, the function views, the cluster views and `catalog_schema` answer.

```sql
-- what can analyst do in sales, and through which grant?
SELECT g.caps."select", g.caps.insert, o.object, o.caps."select" AS object_select
FROM platform.grants g LEFT JOIN platform.object_grants o USING (role, catalog)
WHERE g.role = 'analyst' AND g.catalog = 'sales';

-- which functions are still uncategorized on this node?
SELECT database, schema, name, kind FROM platform.function_status WHERE status = 'uncategorized';
```

## The functions

`platform.main.<op>(…)` - one per management operation, the `acl_*` writer under its plain name.

### How a call is written

- **At the top level only:** `SELECT platform.f(…)` (one select item, no FROM, WHERE, CTE, GROUP BY,
  ORDER BY or set operation) or `CALL platform.f(…)`. Anywhere else - in FROM, a subquery, per row of
  another selection, a WHERE - it is refused at rewrite (`platform.f is a management function - call it
  at the top level of a statement`). A batch mixing calls and queries is refused.
- **Arguments** by position or by name (`name := value`, the names below). An argument may be a
  constant, a list literal (`['select', 'insert']`) or a parameter (`?` / `$1`) - except the arguments
  that **carry authorization** (marked \* below: a catalog, a role, an object, a scope), which must be
  constants: they are judged before the call runs. Nothing else is an argument (a column, a call, a
  subquery is refused - a management call reads no data). A left-out argument takes the function's
  default.
- **Typed arguments:** `caps` takes a capability list (`['select', 'insert']` = `{"select": true,
  "insert": true}`) or the caps JSON; `columns` / `members` a list or the csv; `main`, `cascade`,
  `prune`, `virtual_only` a BOOLEAN. Issuer / client / resource-group specs stay JSON - that is their
  contract.
- **Each call is one change, one `admin` audit event, its own policy-catalog transaction** - a client's
  `ROLLBACK` does not undo it, as for the grammar. The grammar compiles into the same calls and is judged
  by the same authorizer: the grammar and a direct call give the same result and the same refusal.

```sql
SELECT platform.create_catalog('sales', comment := 'the sales mart');
CALL platform.add_relation('sales', 'orders', 'pg.public.orders', columns := ['id', 'amount']);
SELECT platform.grant_catalog(role := 'analyst', catalog := 'sales', caps := ['select'], main := true);
SELECT platform.comment('sales', 'orders', column_name := 'amount', comment := 'in cents');
-- prepared, the payload bound later (the catalog stays a constant)
SELECT platform.alter_catalog('sales', comment := ?);
```

### The functions and the right each needs

Right: **CATALOG** - `policy`, or `manage` on the catalog its `catalog` argument names; **POLICY** -
`policy`; **HANDS_OUT** - `policy` (handing out access); **ESCALATES** - `passthrough` only;
**INFRASTRUCTURE** - the `cluster` bundle (spec 118; a data-path setting `passthrough`'s); **OPERATE** (the
node's runtime) - the `operate` bundle (spec 118). A point grant on the function stands in for a bundle, except for
ESCALATES and INFRASTRUCTURE.

| Function | Parameters (\* authorization, a constant) | Right |
| --- | --- | --- |
| `create_catalog` | catalog\*, comment, mode | CATALOG |
| `alter_catalog` | catalog\*, comment | CATALOG |
| `add_relation` | catalog\*, name\*, phys\*, columns, rls, comment, mode, primary_key | CATALOG |
| `add_view` | catalog\*, name\*, sql, returns, comment, mode, primary_key | CATALOG |
| `add_schema_alias` / `expand_schema` | catalog\*, path\*, phys_path\*, comment, mode | CATALOG |
| `refresh_schema_objects` | catalog\*, path\*, prune | CATALOG |
| `add_table_function` | catalog\*, name\*, definition, params, returns, comment, mode, primary_key | CATALOG |
| `add_table_function_alias` | catalog\*, name\*, target\*, params, returns, comment, mode | CATALOG |
| `add_scalar` | catalog\*, name\*, definition, params, returns, comment, mode | CATALOG |
| `add_scalar_alias` | catalog\*, name\*, target\*, params, returns, comment, mode | CATALOG |
| `drop_relation` | catalog\*, name\*, mode | CATALOG |
| `alter_relation` | catalog\*, name\*, property\*, value | CATALOG |
| `alter_schema_alias` | catalog\*, path\*, phys_path\* | CATALOG |
| `alter_function` | catalog\*, name\*, kind\*, form\*, definition | CATALOG |
| `drop_schema_alias` | catalog\*, path\*, mode, cascade | CATALOG |
| `drop_function` | catalog\*, name\*, kind\*, mode | CATALOG |
| `comment` | catalog\*, name\*, kind\* (default `relation`), column_name\*, comment | CATALOG |
| `refresh_schema` | catalog\*, name\* | CATALOG |
| `repair_relation` | catalog\*, name\*, action\*, spec | CATALOG |
| `set_key` | catalog\*, name\*, kind\*, primary_key | CATALOG |
| `add_reference` | catalog\*, name\*, from_object\*, to_object\*, to_kind, arguments, pairs, expression, cardinality, optional, join_method, comment, mode | CATALOG |
| `drop_reference` | catalog\*, name\*, mode | CATALOG |
| `rematerialize_schema_caps` | catalog\*, path\* | CATALOG |
| `grant_catalog` | role\*, catalog\*, caps, main, rls, columns | HANDS_OUT |
| `revoke_catalog` | role\*, catalog\* | HANDS_OUT |
| `grant_object` | role\*, catalog\*, name\*, caps, rls, columns | HANDS_OUT |
| `grant_schema` | role\*, catalog\*, path\*, caps, comment, into_schema\*, virtual_only | HANDS_OUT |
| `revoke_schema` | role\*, catalog\*, path\* | HANDS_OUT |
| `alter_grant` | role\*, catalog\*, property\*, value | HANDS_OUT |
| `drop_catalog` | catalog\*, cascade, mode | HANDS_OUT |
| `create_role` / `alter_role` | role\*, claims (, mode) | POLICY |
| `drop_role` | role\*, mode | POLICY |
| `define_issuer` | name\*, spec, mode | POLICY |
| `alter_issuer` | name\*, spec | POLICY |
| `drop_issuer` / `drop_client` | name\*, mode | POLICY |
| `define_client` | name\*, issuer\*, spec, mode | POLICY |
| `alter_client` | name\*, spec | POLICY |
| `map_role` / `drop_role_mapping` | scope_kind\*, scope_name\*, source\*, external_value\*, role\* | POLICY |
| `create_function_category` | category\*, comment | POLICY |
| `drop_function_category` | category\*, mode | POLICY |
| `function_category_add` / `_remove` | category\*, members\* | POLICY |
| `grant_function_category` | role\*, category\*, allowed | POLICY |
| `revoke_function_category` | role\*, category\* | POLICY |
| `grant_function` | role\*, function\*, allowed | POLICY |
| `revoke_function` | role\*, function\* | POLICY |
| `session_profile` | session\*, level | OPERATE |
| `session_audit_level` | session\*, level (`''` inherits) | OPERATE |
| `kill_session` | session\* | OPERATE |
| `drain` / `resume` | - | OPERATE |
| `migrate_catalog` | database\*, schema\* | ESCALATES |
| `create_resource_group` | group_name\*, limits, comment, is_default | POLICY |
| `alter_resource_group` | group_name\*, property\*, value | POLICY |
| `drop_resource_group` | group_name\*, mode | POLICY |
| `grant_resource_group` / `revoke_resource_group` | role\*, group_name\* | POLICY |
| `grant_admin` | role\*, scope\* | ESCALATES |
| `revoke_admin` | role\*, scope\* (omitted: everything) | ESCALATES |
| `grant_platform` | role\*, kind\*, object\*, allowed | ESCALATES |
| `revoke_platform` | role\*, kind\*, object\* | ESCALATES |
| `cluster_extension` | verb\*, scope\*, name\*, version, repository\*, comment | INFRASTRUCTURE |
| `cluster_attach` | scope\*, alias\*, path\*, type\*, secret\*, options, depends_on\*, comment, lineage | INFRASTRUCTURE |
| `cluster_detach` | scope\*, alias\*, cascade, force | INFRASTRUCTURE |
| `cluster_setting` | verb\*, scope\*, name\*, value | INFRASTRUCTURE |

The parameters mean what the matching `acl_*` function's do - see the
[management SQL reference](management-sql.md).

### Read functions, in FROM

- `platform.check_catalog([catalog])` - the catalog check of spec 039 (one row per finding with its
  repair statement), judged like `CHECK VIRTUAL CATALOG`: a catalog admin on its catalogs, `policy`
  without an argument. `CALL platform.check_catalog('sales')` is the same.
- `platform.console_info()` - what a console reads to show only what works: `build`,
  `audit_contract`, `connection_contract`, the catalog schema and window (`schema_build`,
  `schema_build_min_reader`, `schema_catalog`, `schema_min_reader`, `schema_mode`), `views` /
  `functions` (what this node has), `my_views` / `my_functions` (what the caller may use), `bundles`
  and `admin_catalogs`. Every principal holding anything on `platform` may call it.

```sql
SELECT bundles, admin_catalogs, my_views FROM platform.console_info();
SELECT problem, object, repair FROM platform.check_catalog('sales');
```

## The grammar without the marker

Under a principal prefix (`ACL ROLE`, `ACL TOKEN`, `ACL SESSION` - every door) the management grammar
needs no `ACL` marker: `GRANT CATALOG sales TO ROLE analyst WITH (select)`, `CREATE ROLE r`, `CREATE
VIRTUAL TABLE …` are written as in any DBMS. A statement is management when its leading phrase is one
of the grammar's (`GRANT` / `REVOKE` / `DENY`, `CREATE|ALTER|DROP ROLE|ISSUER|CLIENT|VIRTUAL …|FUNCTION
CATEGORY|RESOURCE GROUP`, `MAP`, `DROP MAP|RELATION`, `ADD`, `CHECK|REPAIR VIRTUAL`, `PROFILE SESSION`,
`CLUSTER`, `COMMENT ON VIRTUAL`, `ANALYZE VIRTUAL`); everything else is an ordinary query - `CREATE
TABLE`, `DROP TABLE`, `ALTER TABLE … RENAME`, duckdb's `COMMENT ON TABLE`, `ANALYZE t` and `CREATE
FUNCTION` are answered as before. `ACL <mgmt>` is still accepted; `ACL ADMIN` and `ACL NATIVE` are
unchanged.

**A batch is all management or all queries**: one mixing them (in either order, the grammar or a
platform call) is refused - send each kind in a batch of its own.

## Schema v21

The platform catalog needs schema version 21: `admins` is keyed `(role, scope, vcat)` (a role holds
several bundles) and `platform_grants` is new. An older catalog is migrated with
`SELECT acl_migrate_catalog('<db>'[, '<schema>'])`; the rows spec 009 wrote read as bundles (`manage`
→ policy + observe, a catalog-scoped `manage` → that catalog, `observe`, `passthrough` as they are) -
nothing is rewritten. The step refuses while a virtual catalog (or a grant on one) is named `platform`:
rename or drop it, then migrate. `min_reader_version` is 21 - a build before it does not know the
bundles and does not serve a v21 catalog.
