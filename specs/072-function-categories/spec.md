# Spec 072: function categories - what a principal may call

- **Status**: implemented - slices 1-3 (2026-09-18: the model, the seed, the gate; the management syntax; the function-driver slots); slice 4 (docs pass) open
- **Date**: 2026-09-18
- **Author**: hugr lab

## Summary

A principal may call a function only if it is in a **category** granted to one of its roles, or is
granted to a role by name; a deny by name or on a category wins over any grant. Categories are rows
in the policy catalog: seeded once when the catalog is created (`base`, `json`, `spatial`, ... granted
to every role; `readers`, `meta`, `environment`, `node`, `plan` granted to nobody), and from then on
changed only by the operator - a newly loaded extension's functions, a function a pin bump adds, a
macro an admin creates are in no category until somebody puts them there. The function's key is
`(database, schema, name, kind)`, not a bare name, so a macro in a physical catalog is a different
function from the builtin it is named after, and the rewriter emits every admitted call qualified to
the key that admitted it. An admin table function joins the node's `duckdb_functions()` with the
categories, so the first screen after `LOAD` shows what is new and uncategorized. This replaces the
denylist (`DefaultDeniedFunctions`, 42 names) and the `function_gate` table.

## Problem

The gate is a denylist. Its failure mode is the thing nobody named, and this month named several:
`json_execute_serialized_sql` (spec 052 addendum), the `VALUES` walk (spec 052 addendum), and what is
still open in `main` after those - measured under a principal holding one grant on an empty catalog:

- a user-defined table or scalar macro over a physical table returns its rows (`CREATE MACRO peek()
  AS TABLE SELECT * FROM phys.payroll` → `FROM peek()`): the body is SQL the rewriter never sees, and
  the name is whatever the author chose, so a denylist cannot name it;
- system macros whose bodies read the catalog or a table named by argument: `pg_get_viewdef(oid)`
  returned a physical view's SQL, `histogram_values(tbl, col)` a physical column's value distribution;
- `nextval` / `setval` / `currval` write a physical sequence;
- `stats(col)` returns min/max and the distinct count over rows RLS hides (design 073);
- the operator's knobs - `checkpoint`, `enable_logging`, `enable_profiling`, ... - are reachable;
- a loaded extension's table functions are open until named (`LOAD spatial` opens `st_read`).

Two facts make a denylist the wrong shape: `duckdb_functions().categories` is empty for 767 of ~1000
scalars, so duckdb offers no classification to lean on; and a name is not a key - a principal's bare
`lower` binds to `memory.main.lower` if an admin (or ducklake's metadata) defines one, ahead of
`system.main.lower`.

## Design

### The model in one sentence

> A call is admitted when its resolved key is in a category granted to the principal, or is granted
> by name; a deny anywhere among the principal's roles - by name or on a category, for a role or for
> every role - wins over any grant; a key in no category is refused.

The seed puts every function in exactly one category, so the shipped model reads as a partition:
`st_read` is `readers`, not `spatial`; `getenv` is `environment`, not `base`. The operator may put a
key in more than one category - a grant on any of them admits it, a deny on any refuses it - and may
split a shipped category into finer ones without duplicating anything (owner's decision, 2026-09-18).
No deny row is ever seeded: what nobody should hold from the start is simply not granted to `''`.

### Data - schema v14

```sql
CREATE TABLE <function_categories>("category" ACL_KEY_TEXT PRIMARY KEY, "comment" VARCHAR, "builtin" BOOLEAN);

CREATE TABLE <function_category_members>("category" ACL_KEY_TEXT, "database" ACL_KEY_TEXT, "schema" ACL_KEY_TEXT,
    "name" ACL_KEY_TEXT, "kind" ACL_KEY_TEXT,                                -- kind: 'scalar' | 'table'
    PRIMARY KEY ("category", "database", "schema", "name", "kind"));

CREATE TABLE <function_grants>("role" ACL_KEY_TEXT,                        -- '' = every role
    "category" ACL_KEY_TEXT,                                                -- a category grant: key columns ''
    "database" ACL_KEY_TEXT, "schema" ACL_KEY_TEXT, "name" ACL_KEY_TEXT, "kind" ACL_KEY_TEXT, -- a name grant: category ''
    "allowed" BOOLEAN,
    PRIMARY KEY ("role", "category", "database", "schema", "name", "kind"));
```

`function_gate` goes. `kind` is two-valued because that is what the rewriter knows before bind: a
name in FROM is `table`, anywhere else `scalar` (scalar, aggregate, window and macro all resolve in
the scalar position). Four builtin names exist in both kinds (`range`, `generate_series`, `repeat`,
`histogram`) and the two are categorized separately - the table macro `histogram(tbl, col)` reads a
table named by argument and belongs to `meta`; the aggregate `histogram(x)` to `base`.

`builtin` marks provenance only. The operator edits a shipped category exactly like an own one;
nothing re-seeds or re-syncs it later (owner's rule: nothing is ever added automatically).
An alias is a member of its own (`read_csv_auto` beside `read_csv`, `len` beside `length`): nothing
follows an alias to its target, in the seed or later - the name written is the name checked.

### The seed

Written once, at catalog creation (`acl_use_db(..., init)`) and in `schema/migrations/v14.sql`; kept
as text files, one per category, `schema/function_categories/<category>.txt`, one member per line as
`[database.schema.]name [TABLE]` (default `system.main`, default kind scalar). `scripts/gen_schema.py`
renders them into the `INSERT`s of `acl_schema.sql`, `acl_schema_sql.hpp` and `v14.sql` - one source,
reviewable by eye, diffable when a pin bump adds or removes names (`make schema-check` stays the
guard that the rendered files are current). The auto grants are seed rows too: `('', 'base', '', '',
'', '', true)` and the like, for the categories marked **auto** below - a grant to every role that any
role may be denied and every role may lose (`REVOKE ... FROM ALL ROLES`), not a flag.

| category | contents (from the 2026-09-15 inventory, design 072 §9) | auto |
| --- | --- | --- |
| `base` | core scalars, aggregates, window functions, the compute macros (`list_*`, `nullif`, `if`, `fmod`, ...), **the operators** (`+`, `~~`, `->>`, ...: the parser hands them over as functions) and the names the parser rewrites syntax into (`count_star`, `list_value`, `struct_pack`, `date_part`, `regexp_full_match`, `factorial`, `list_apply`, ...); `duckdb_format_sql`, `stem`, `excel_text`, `text`, parquet's `variant_*` | yes |
| `generators` | `range`, `generate_series`, `unnest`, `repeat`, `repeat_row`, `summary`, `test_vector_types`, `sql_tokenize`, `check_peg_parser`, `tpch_queries`, `tpch_answers`, `tpcds_queries`, `tpcds_answers` | yes |
| `node_facts` | `duckdb_keywords`, `duckdb_dialects`, `duckdb_coordinate_systems`, `duckdb_available_metrics`, `duckdb_optimizers`, `duckdb_secret_types`, `duckdb_secret_type_parameters`, `duckdb_grammar_extensions`, `pragma_platform`, `pragma_collations`, `pragma_version`, `pragma_user_agent`, `icu_calendar_names`, `pg_timezone_names` | yes |
| `json` | `json_*` scalars and aggregates, `json_each`, `json_tree`, `json_serialize_sql`, `json_deserialize_sql` (they parse and print; a serialized statement is JSON anyone writes) | yes |
| `icu` | icu's 289 scalars | yes |
| `spatial` | `st_*` except the readers and `st_drivers` | yes |
| `inet`, `h3`, `hashfuncs`, `a5`, `geosilo` | one per extension, all pure compute (`geosilo`'s `ST_*` overloads are `spatial`'s names) | yes |
| `readers` | `read_csv*`, `sniff_csv`, `read_text`, `read_blob`, `glob`, `read_duckdb`, `read_parquet`, `parquet_scan`, `parquet_*metadata`, `parquet_schema`, `parquet_bloom_probe`, `read_json*`, `read_ndjson*`, `read_single_json_file`, `st_read*`, `read_xlsx`, `read_avro`, `read_vortex`, `lance_*`, `delta_scan`, `delta_list_files`, `delta_get_transaction_version`, `iceberg_scan`, `iceberg_metadata`, `iceberg_snapshots`, `vss_join`, `vss_match`, the scanners' `*_scan*` | no |
| `meta` | the `duckdb_*` listings the rewriter does not substitute (spec 035 substitutes tables/columns/schemas/databases/views), `pragma_database_size/metadata_info/show/storage_info/table_info`, `show_databases/show_tables/show_tables_expanded`, `sql_auto_complete`, `histogram_values`, the table macro `histogram`, `stats`, `st_drivers`, the pg-compatibility macros that read the catalog (`pg_get_viewdef`, `pg_get_expr`, `pg_get_constraintdef`, `obj_description`, `col_description`, `shobj_description`, `has_*_privilege`, `pg_*_is_visible`, `inet_client_*`, `inet_server_*`, `pg_postmaster_start_time`, `pg_conf_load_time`, `format_type`), `current_connection_id`, `current_query_id`, `current_transaction_id` | no |
| `environment` | `getenv`, `current_setting`, `getvariable`, `which_secret`, `current_query`, `duckdb_secrets`, `duckdb_settings`, `duckdb_variables` | no |
| `node` | `checkpoint`, `force_checkpoint`, `enable/disable_logging`, `truncate_duckdb_logs`, `enable/disable_profiling`, `write_log`, `sleep_ms`, `pg_sleep`, `nextval`, `currval`, `setval`, `create/register/deregister/destroy_external_resource`, `register_external_resource_type`, `dbgen`, `dsdgen`, `load_aws_credentials`, `start_ui*`, `stop_ui_server`, `notify_ui`, `delta_set_transaction_version`, `iceberg_to_ducklake`, `unity_catalog_checkpoint_table` | no |
| `plan` | `json_serialize_plan`, `get_substrait`, `from_substrait` | no |

Names of extensions the node does not carry are in the seed anyway: a member without a function
admits nothing, and loading the extension later needs nobody's hand for what the seed already
decided.

**Never** - a set in code, not in data, shown as the category `never` by the admin function and
refused at write time ("only ACL NATIVE can run these"): `acl_*`, `ducklake_*`, `quack_*`,
`arrow_scan`, `arrow_scan_dumb`, `seq_scan`, `query`, `query_table`, `json_execute_serialized_sql`,
`tpch`, `tpcds`, `sqlsmith`, `fuzzyduck`, `reduce_sql_statement`, `fuzz_all_functions`, `uc_*`, the
scanners' `*_query`, `*_execute`, `*_attach`, `*_clear_cache` and pool/connection knobs, and the
engine's own helpers no statement spells by name - `__internal_*`, `error`, `constant_or_null`,
`create_sort_key`, `invoke`, `combine`, `finalize`, `to_aggregate_state`. Each either runs SQL past the rewriter
(here or on another server under the node's credentials) or dereferences a pointer: whoever needs one
needs `ACL NATIVE`, and has it. In data it could be edited away; in code it cannot.

### Resolving one call (the rewriter, before bind)

For a `FunctionExpression`, a `WindowExpression` (gated for the first time: `sum(x) OVER ()` is a
`WINDOW` node, not a `FUNCTION` one) and a table function in FROM - after virtual functions (spec
022) and the listing substitutions (spec 035), which resolve first as today, and after the two
door exemptions (spec 042's own drain, spec 049's own ingest), which stay as they are:

1. **Never**: name in the set → refused, whatever the data says.
2. **Key.** A bare name is looked up among the members of that name and kind, in this order:
   `system.main`, `system.pg_catalog`, other `system.*` schemas (extension schemas, duckdb 2.0),
   then non-system keys; two non-system candidates → refused as ambiguous ("qualify it"). A
   qualified name (`lake.main.peek()`, `system.pg_catalog.pg_typeof(x)`) is its own key as written.
   A qualified name that is no member is a method call (`x.lower()` parses as `lower` in schema `x`,
   `t.x.lower()` as catalog `t`, schema `x`): rewritten to `lower(x)` over the column reference and
   resolved as bare; if `x` is not a column the binder says so.
3. **Verdict**, over the principal's roles plus `''`, flat - no precedence ladder: any deny by
   name → refused; any deny on a category holding the key → refused; otherwise a grant by name, or a
   grant on any category holding the key → admitted; else refused (`Reason::FUNCTION_DENIED`, the
   text names the function as written and the key it resolved to, or "in no category"). "All readers
   but `read_text`" is a grant on `readers` and a deny on the name; "`read_parquet` and nothing else"
   is a grant on the name and no grant on `readers` - both directions without a ladder.
4. **The call is emitted qualified** to the key that admitted it: `lower(x)` → `system.main.lower(x)`,
   `pg_typeof(x)` → `system.pg_catalog.pg_typeof(x)`, `peek()` granted as `lake.main.peek` →
   `lake.main.peek()`. This is what makes a grant on `system.main.lower` mean that function: an admin
   macro named `lower` in the default catalog no longer takes the call (verified live: today it
   does, and returned a table no grant names). Verified on the pin: qualification binds for
   scalars, aggregates, windows, operators (`system.main."+"(1, 2)`), lambdas, `unnest`, and table
   functions in FROM.
5. **The keyword spellings** (`current_user`, `session_user`, `current_role`, `user`, `current_date`,
   `current_time`, `current_timestamp`, `localtime`, `localtimestamp`) are column references to the
   parser; the binder turns them into calls only after the rewrite, and only when no column of that
   name binds. They are left alone: every one resolves to a `base` function that answers a constant
   (`'duckdb'`) or a clock, so there is nothing to reach through them, while converting them ahead of
   the gate would make a column named `user` lose to the keyword - a worse trade than a deny on
   `current_user` not reaching its keyword spelling, which is documented instead.

The per-principal table - name/kind → admitted key - is built when the policy loads (roles' grants
∪ `''`), cached per role signature like `gates` today, and invalidated by `policy_version`. One
hash lookup per call on the query path; the categories are `unordered_set`s of a few thousand keys.

**Known residual, not a mechanism.** An admin macro named like a builtin still takes the name where
the principal did not write it: masks, RLS predicates, view bodies and system-macro bodies resolve
bare names in the binder, so a macro `md5` in the default catalog answers a mask `md5(email)` (verified).
That is the admin's own action against the admin's own policy; the admin function flags such
macros (`shadows_system`) and `acl_check_catalog` (spec 039) reports them.

### Syntax

Management SQL (spec 008 style: compiled into admin functions, no parse-time side effects):

```sql
ACL ADMIN CREATE FUNCTION CATEGORY gis_readers [COMMENT 'st_read for the GIS team'];
ACL ADMIN DROP FUNCTION CATEGORY gis_readers;                        -- and its grants; a builtin one too
ACL ADMIN ALTER FUNCTION CATEGORY gis_readers ADD (st_read TABLE, st_read_meta TABLE, lake.main.peek TABLE);
ACL ADMIN ALTER FUNCTION CATEGORY base DROP (md5_number_upper);

ACL ADMIN GRANT FUNCTION CATEGORY gis_readers TO ROLE gis;
ACL ADMIN GRANT FUNCTION CATEGORY spatial TO ALL ROLES;              -- role ''
ACL ADMIN REVOKE FUNCTION CATEGORY spatial FROM ROLE gis | ALL ROLES; -- the row goes
ACL ADMIN DENY FUNCTION CATEGORY base TO ROLE quarantine;            -- allowed = false: wins

ACL ADMIN GRANT FUNCTION lake.main.peek TABLE TO ROLE analyst;       -- an admin's macro: only this way
ACL ADMIN GRANT FUNCTION read_parquet TABLE TO ROLE etl;              -- unconfined: the answer says so
ACL ADMIN DENY FUNCTION getenv TO ROLE etl;
ACL ADMIN REVOKE FUNCTION lake.main.peek TABLE FROM ROLE analyst;
```

- A bare name written here is `system.main` if such a member or function exists, else
  `system.pg_catalog`; `TABLE` after a name selects the kind (default scalar).
- A key is checked against the writing node's `duckdb_functions()`: no such function → refused,
  unless `kind` was written explicitly - so a fleet-shared catalog can carry a function of an
  extension the writing node does not have.
- A key in the never set → refused at write time.
- Bulk from a selection is the native mode, as the owner asked:
  `ACL NATIVE SELECT acl_function_category_add('myext', list(function_name)) FROM duckdb_functions() WHERE function_name LIKE 'myext_%';`
- A category acts in every catalog a role holds, so writing categories and function grants takes
  **global `manage`** (spec 009); a catalog-scoped `manage` does not reach them.

Admin functions (the compile targets, also callable): `acl_create_function_category(name[, comment])`,
`acl_drop_function_category(name)`, `acl_function_category_add(name, members)` /
`acl_function_category_remove(name, members)` (members: a list, or a csv string, each item
`[db.schema.]name[ TABLE]`), `acl_grant_function_category(role, category[, allowed])`,
`acl_revoke_function_category(role, category)`, `acl_grant_function(role, name[, kind[, allowed]])`,
`acl_revoke_function(role, name[, kind])`. `ALL ROLES` is `role = ''`. The legacy
`acl_deny_function(name)` / `acl_allow_function(name)` stay as wrappers over `acl_grant_function('',
name, <both kinds>, false|true)` - what `test/sql/acl.test` and the harness use today keeps working.

### What the admin sees

- `acl_function_status([role])` - the node's `duckdb_functions()` collapsed to keys `FULL JOIN` the members:
  `database, schema, name, kind, function_type, internal, categories LIST, status ∈ {never,
  categorized, uncategorized}, present BOOLEAN` (a member with no function on this node),
  `shadows_system BOOLEAN`; with a role: `allowed BOOLEAN, decided_by` (`name:<role>`,
  `category:<cat>@<role>`, `never`, `none`). The screen after `LOAD`: `WHERE status = 'uncategorized'`.
- `acl_function_categories()` - `category, comment, builtin, members, present, granted_to LIST`.
- The introspection listings gain `acl_function_categories`, `acl_function_category_members`,
  `acl_function_grants` (and lose `acl_function_gate`); `acl_policy()` lists them.

### Policy sources

- **Catalog mode**: the tables above.
- **Memory mode** (no catalog, the dev stub): the seed from the generated header plus the auto
  grants, in `PolicyStore`; `acl_deny_function` / `acl_allow_function` write `''`-role name grants
  there, as they fill the in-memory store today.
- **Function driver** (spec 008): three slots, positional contracts mirroring the tables -
  `function_categories(name)`, `function_category_members(category)`,
  `function_grants(roles, name)`; a source without them behaves as memory mode does (seed + auto),
  the way a missing `function_gate` slot fell back to the denylist.

### Migration

`schema/migrations/v14.sql`: create the three tables, insert the seed and the auto grants, convert
`function_gate` - each `(role, name, kind, allowed)` row becomes two name grants, `scalar` and
`table`, since today's `kind` is written as `''` - then drop it, then stamp 14. `make schema-check`
proves a migrated catalog and a fresh one have the same shape (spec 034).

### Interaction

- Virtual functions (`acl_add_table_function` / `acl_add_scalar`, spec 022) resolve before the gate
  and are the confined way to a reader: a virtual table function over `read_parquet` with the path
  baked. A grant on `readers` is the unconfined way and the answer to the grant says so.
- The listings the rewriter substitutes (spec 035) never reach the gate; unchanged.
- `EXPLAIN` stays spec 052's capability; `plan` is a category like any other (decision 1).
- The identity substitutions (`current_database()` and its keyword, spec 052 addendum) happen before
  the gate; unchanged.
- The audit's refusal reason code stays `function_denied`; the text carries the function as
  written and the key, both from bounded sets.

## Enforcement & security

- **Default deny**: a function in no granted category is refused - a new extension's functions, a
  pin bump's new builtins, an admin's macro, a ducklake macro all start there. The denylist's
  failure mode (the thing nobody named) is gone.
- **The key is the function**: the rewriter's qualification makes a grant name one function, so a
  shadowing macro in a physical catalog cannot take a principal's call.
- **Never is code**: the set that is equivalent to `ACL NATIVE` cannot be granted, whatever the data
  says, and the write path refuses it with the reason.
- **Fail closed on ambiguity**: two non-system candidates for a bare name refuse rather than pick.
- **Nothing on the query path reads the source** (spec 065): resolution is a lookup in a table built
  from the policy at load time; `duckdb_functions()` is consulted only when the admin writes.
- **Deny wins** across roles, for names and categories alike, the way a denied name wins today.
- **The seed is reviewed**: a builtin macro enters an auto category only after its body was read
  (`macro_definition`); the drift test below keeps it so.

## Testing

1. `acl_function_categories.test`: every rule of the resolution - the schema order for a bare name,
   a qualified key, a method call, the ambiguity refusal, deny by name over a category grant, deny on
   a category over another role's grant, `''` grants and their revocation, the never set refused at
   write time, `TABLE` selecting the kind, both kinds of `histogram`.
2. `acl_function_syntax_forms.test`: a principal with only the auto categories runs ordinary SQL -
   operators, the parser's rewritten names, windows, lambdas, list comprehensions, `x.lower()`, the
   pg-compatibility macros by bare name, `EXTRACT`, `SIMILAR TO`, `[...]`, `{...}`.
3. The gaps of design 072 §10 closed: `pg_get_viewdef`, `histogram_values`, the table macro
   `histogram`, `nextval`/`setval`, the node knobs, `stats`, an admin's macro `peek` (refused without
   a grant, answering under a grant on its key), a macro in a ducklake catalog.
4. Qualification: an admin macro `lower` in the default catalog does not take a principal's `lower()`.
5. The keyword spellings converted ahead of the gate (`current_user` refused while `meta` is not
   granted).
6. Windows gated: `sum(x) OVER ()` with `sum` removed from `base` for a role is refused.
7. Drift: every function of the build is in the seed, in the never set, or listed in
   `schema/function_categories/unsorted.txt` - and the test fails while `unsorted.txt` is not empty;
   every seed member for an extension the build links exists. Every macro in an auto category has a
   body without `duckdb_*`, `pragma_*`, `query*` and no table-name argument.
8. `make schema-check`: the seed renders identically into the three outputs; `v14.sql` from a v13
   catalog with `function_gate` rows gives the converted grants and the same shape as a fresh
   catalog.
9. Management syntax round trips (`acl_ddl_syntax.test` style) and the `acl_function_status()` screen:
   `uncategorized` after a synthetic `CREATE MACRO`, `never` for `query_table`, `decided_by` for a
   role.
10. Harness and both doors' e2e unchanged: the demo's functions are all `base`.

## Implementation notes (slice 1, 2026-09-18)

- The model is `FunctionCategoryModel` (`src/include/acl_function_categories.hpp`,
  `src/acl_function_categories.cpp`): built from rows, immutable, swapped whole. The catalog backend
  builds it from the three tables on first use after a policy-version bump (`CatalogBackend::
  FunctionModel`); memory mode starts from the seed (`src/acl_function_seed.hpp`, generated by
  `gen_schema.py` beside the schema) and a writer copies, edits and swaps (`EditMemoryFunctions`);
  a function-driver source without the slots reads as the seed until slice 3.
- `PolicyStore::ResolveFunction` replaced `FunctionAllowed`; `DefaultDeniedFunctions` and the
  `function_gate` table are gone (`schema/migrations/v14.sql` converts its rows to grants by name for
  both kinds and seeds the categories exactly as a fresh catalog is - the region between
  `@seed-begin` / `@seed-end` is generated).
- The rewriter gates `FunctionExpression`, `WindowExpression` (first time a window function is gated)
  and the table function in FROM through one `GateFunction`, which rewrites the admitted call to its
  key; a qualified name that is no member is retried as duckdb's method-call spelling (`x.lower()`
  → `lower(x)`). Result columns keep the names duckdb gives them: `KeepItemNames` aliases every
  select item that is not a star, a column reference or a constant with its own name before the
  rewrite - a column reference aliased to itself is a self-reference to the binder when it is a
  keyword resolved late (`SELECT current_date`), hence the exclusion.
- `unnest` in the select list is the scalar position of a table function: the seed carries
  `unnest` in `generators` for both kinds. The operator's screen is `acl_function_status([role])` -
  `acl_functions()` was already the listing of virtual functions. `current_user`, `user`,
  `session_user`, `current_role` are `base` (they answer `'duckdb'`, a constant), not `meta`.
- The never set gained the engine's own helpers (`__internal_*`, `error`, `constant_or_null`,
  `create_sort_key`, `invoke`, `combine`, `finalize`, `to_aggregate_state`): no statement spells
  them by name, and "uncategorized" would have listed them on every node forever.
- Tests: `acl_function_categories.test` (the rules, the seed, the never set at write, an admin's
  macro, the shadowing macro, the method call, the operator's own category, the legacy pair, the
  status screen), `acl_function_syntax_forms.test` (every syntactic form the parser turns into a
  call, the headers, a denied window function); the drift check is the status screen's
  `uncategorized AND present` count, which is 0 for this build. The existing suite needed two
  changes: the never set refused where an allow is written (`acl_serialized_sql_gate.test`), and a
  function-driver source without the slots deciding by the seed (`acl_functions_driver.test`).

## Implementation notes (slice 2, 2026-09-18)

- The management grammar (`acl_admin_sql.cpp`): `CREATE FUNCTION CATEGORY c [COMMENT '…']`, `ALTER
  FUNCTION CATEGORY c ADD (…) | DROP (…)`, `DROP FUNCTION CATEGORY [IF EXISTS] c`, `GRANT | DENY |
  REVOKE FUNCTION [CATEGORY] … TO | FROM ROLE r | ALL ROLES` - each compiled into the slice-1 admin
  functions. `DENY` is a new first keyword (duckdb has none); `CREATE/ALTER/DROP FUNCTION CATEGORY` is
  told apart from duckdb's own `CREATE FUNCTION` (a macro) by the third word, so `ACL ADMIN CREATE
  FUNCTION f(x) AS …` stays native. A function spec is a dotted name or a double-quoted operator with
  an optional `TABLE`/`SCALAR`, passed to the admin function as written. Every one is "not
  catalog-specific" in `ProvenanceOf`: a catalog-scoped manage is refused.
- The write-time check (`RequireFunctionOnNode`): a member or an admitting grant names a function this
  node has - read off `duckdb_functions()` on a connection of its own, with the calls in the check
  query qualified (`system.main.lower`), since an admin's macro named `lower` in the default catalog
  answered the first version of it. Skipped when the kind was written explicitly; a deny or a revoke
  never checks.
- The per-role decision cache the owner asked for: `PolicyStore::ResolveFunction` caches the verdict
  per sorted role set, name as written and kind, against the model it was made with (4096 entries,
  cleared when the model swaps or the cap is hit). The model itself was already one lookup; this
  skips even that.
- Tests: `acl_function_syntax.test` (every form, `ALL ROLES`, a deny and a revoke, grants by name on
  a builtin, an admin's macro and an operator, the write-time check and the explicit-kind escape,
  the never set in every form, `DROP … IF EXISTS`, duckdb's `CREATE FUNCTION` staying native, the
  scope).

## Implementation notes (slice 3, 2026-09-18)

- The function-driver source (spec 008) reads its categories from three slots -
  `function_categories()`, `function_category_members()`, `function_grants()` - each a listing with
  no arguments and the columns the tables have. Not the keyed lookups the draft named: the model is
  built once per policy version from the whole set, so a keyed contract would have bought nothing
  and cost a source call per name. `CatalogBackend::FunctionModel` builds from the slots exactly as
  from the tables; the slots are declared together or not at all (`acl_use_functions` refuses a
  partial set at enable - members without grants would read as "nothing granted"), and a source
  without them reads as the seed. The pre-072 `function_gate` slot is not read.
- `acl_functions_driver.test` covers the partial map, a source whose own categories decide (a builtin
  the source never listed is refused, seed or not), a deny by name from the source, and the listings
  answering from the source's rows.

## Implementation plan (for agreement)

| slice | what | touches |
| --- | --- | --- |
| 1 | schema v14 + seed files + generator + migration; `PolicyStore` resolution (catalog, memory), the rewriter's key/qualification/windows/keywords/method call; `DefaultDeniedFunctions` and `function_gate` go; tests 1-8 | `schema/policy_schema.sql`, `schema/function_categories/*.txt`, `scripts/gen_schema.py`, `schema/migrations/v14.sql`, `src/acl_schema_sql.hpp` (generated), `acl_policy.cpp/.hpp`, `acl_policy_catalog.cpp/.hpp`, `acl_rewriter.cpp`, tests |
| 2 | management syntax, admin functions, `acl_functions` / `acl_function_categories`, introspection listings; test 9; `docs/management-sql.md` | `acl_admin_sql.cpp`, `acl_admin_functions.cpp`, `acl_catalog_admin.cpp`, `acl_metadata_listing.cpp`, `acl_introspection.cpp`, docs |
| 3 | function-driver slots | `acl_policy_catalog.cpp`, spec 008 test |
| 4 | `docs/security.md`, CLAUDE.md, README | docs |

Size: the seed is ~1,400 member rows (largest: `base` ~600 with operators, `icu` 289, `spatial`
~176); the code is ~600 lines in the store and rewriter, ~500 in syntax and admin functions, plus
tests. Slice 1 closes every open gap on its own and is the PR to land first; slices 2-3 can follow
in a day each.

## Decisions to agree

1. **`plan` is a plain category** granted explicitly (proposed), not implied by the `explain`
   capability. Fewer hidden rules; a role that may see plans is granted `plan` in one more line.
2. **Every admitted call is emitted qualified** to its key (proposed). Risk: a binder special case
   that matches a bare name only; the pin check found none (`unnest`, lambdas, operators, windows
   all bind qualified), and test 2 is the guard. Fallback if one appears: qualify only names that
   have a non-system member of the same name.
3. **`function_gate` rows migrate** to name grants for both kinds (proposed), rather than being
   dropped: the deny rows an operator wrote keep denying.
4. **The seed lives in text files** rendered by `gen_schema.py` (proposed), one file per category -
   readable without a build, reviewable in a PR line by line.
5. **Category and function-grant writes need global `manage`** (proposed): a category reaches every
   catalog, so a catalog-scoped admin cannot widen the function surface.
6. **`acl_deny_function` / `acl_allow_function` stay** as wrappers over `''`-role name grants
   (proposed): the memory-mode tests and the harness keep working unchanged.
7. **Ambiguous bare names refuse** (proposed) rather than first-match: with two non-system
   candidates the rewriter cannot know which the principal meant.
8. **Auto categories are seeded `''` grants** (proposed): visible in `acl_function_grants`, revocable
   for all or denied per role, no second mechanism.
10. **Union, not intersection** (owner, 2026-09-18): a key in several categories is admitted by a
   grant on any of them and refused by a deny on any; the seed keeps categories disjoint (one per
   function), and a shipped category can be split into finer ones without duplicating a member. The
   alternative - every category a key sits in must be granted - was considered and set aside: it
   reads as a requirement rather than a permission, and disjoint categories give the same control.
9. **Aliases are names** (owner, 2026-09-18): a function's alias is its own member, seeded and
   granted by hand exactly like the function - nothing follows an alias to its target at any point,
   in the seed, in the writer or in the rewriter. Simpler, and it keeps the one rule: what is in the
   category is what is callable, by the name written.

## Alternatives considered

- **Classes with defaults and extension attribution** (design 072 §7): rejected by the owner - it
  leans on load hooks and "which extension owns this", and a loaded extension widens the surface
  before anyone looks.
- **Compiled lists, not tables** (design 072 §8): the seed compiled in, lists shipped as code. The
  owner wanted the lists in the policy database, editable by the operator and fleet-shared like
  every other policy row; the seed still comes from files, but lands as rows.
- **Keep scalars default-allow, deny table functions by default**: half the model, and it leaves
  `stats`, `pg_get_viewdef`, `nextval` open by name - the class of gap that keeps recurring.
- **Bind-time hooks** (PlannerExtension) to decide what a name resolves to: rejected - the decision
  belongs before bind, in the rewriter, where every other decision is made and audited.

## Follow-ups

- Auto-detection of a macro that shadows a builtin, as an `acl_check_catalog` finding (`shadows_system`).
- An `EXPLAIN`-bound `plan` if decision 1 is reversed.
- The scanners' `*_scan` in `readers` are unconfined by construction (any table of the attached
  source); the confined way remains a virtual relation - documented, not solved here.
