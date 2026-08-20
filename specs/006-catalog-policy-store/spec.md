# Spec 006: catalog-backed policy store (virtual catalogs, phase 1)

- **Status**: implemented
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

Phase 1 of the role-aware resolver (design: `design/002-role-aware-resolver`, local): policy moves
from in-memory stubs to a **catalog database** — any ATTACHed source, spoken to only in standard
duckdb dialect (source agnostic, the ducklake-catalog idea). The model separates **virtual catalogs**
(shared trees of virtual names with replacement forms, masks, RLS templates) from **role grants**
(which catalogs a role sees, with what capabilities). The in-memory store remains the default
dev/test mode; the rewriter does not change — everything lands behind the `PolicyStore` seam.

## Problem

Policy lives in process memory, per instance, populated by `acl_grant_*` stubs: nothing is
persistent, shareable between instances, or manageable by a platform. The production model
(gateway + many DuckDB instances over external sources) needs one external policy source that any
instance can attach, with bounded staleness and no per-request round-trip storms.

## Design

### Enabling the catalog

```sql
ATTACH 'dbname=aclmeta ...' AS aclcat (TYPE postgres);   -- any scanner, or a duckdb file
SELECT acl_use_db('aclcat');                             -- read policy from schema 'acl'
SELECT acl_use_db('aclcat', 'security');                 -- schema name as a parameter
SELECT acl_use_db('aclcat', 'acl', true);                -- init := true creates/migrates the schema
```

`acl_use_db(name [, schema [, init]])` switches the store to the catalog backend. Reads run on
short-lived connections on the same `DatabaseInstance` (a stored connection would cycle
instance → config → store → connection; the ducklake precedent), issuing standard-dialect SQL with
literal predicates — scanners push the filters down.
Without `acl_use_db` the in-memory backend keeps working exactly as before.

### Schema (managed mode, `init := true`)

Portable types only; `acl` is the default schema name. `PRIMARY KEY (vcat, vname)` makes object
definitions conflict-free by construction — roles only select which catalogs they see. **Every**
table carries a primary key: sources without rowids need one for DELETE/UPDATE (`function_gate`
therefore encodes "global"/"any kind" as `''`, never NULL).

- `acl.meta(key, value)` — `schema_version`, `policy_version` (bumped on every admin write, same
  transaction).
- `acl.catalogs(vcat, comment)`; `acl.relations(vcat, vname, form 'alias|subquery|view', phys,
  view_sql, rls)`; `acl.relation_columns(vcat, vname, pos, name, expr)`;
  `acl.schema_aliases(vcat, alias_path, phys_path)`; `acl.functions(vcat, vname, kind
  'table|scalar', form 'alias|macro', target, template)`.
- `acl.roles(role, comment)`; `acl.role_claims(role, claim, value)`;
  `acl.role_catalogs(role, vcat, is_main, caps)`; `acl.role_object_caps(role, vcat, vname, caps)`;
  `acl.function_gate(role NULLable, name, kind, allowed)`.
- `caps` is a JSON object (`{"select": true, "insert": true}`), stored as VARCHAR; extensible
  without schema migration. Parsed with duckdb's bundled yyjson (already linked into the core) —
  anything but a flat object of booleans is refused.

(Issuer/token tables arrive with spec 007; `acl.admins` with spec 009.)

### Resolution (catalog backend)

The principal is now **multi-role** (`Principal.roles`); phase 1 plumbs the vector through (union
semantics), real multi-role principals arrive with JWT (007). For a name written as `a.b...rel`:

The selection runs **in SQL**, not in C++: one resolve miss is a single JOIN over
`role_catalogs`/`relations`/`role_object_caps` (projected columns folded in as a `list()`
aggregate), with the qualified-vs-main interpretation, the unique-main guard and the per-role
effective caps decided by the query; the alias fallback is a second JOIN picking the longest
granted prefix via `ORDER BY length(alias_path) DESC`. duckdb's engine does the work and the
base-table filters push down into the scanners.

1. If the first component is a catalog granted to any of the principal's roles → resolve the rest
   inside that catalog: exact `relations` hit, else the longest `schema_aliases` prefix (an alias
   RENAMEs the prefix in place; the binder validates existence), else deny.
2. Otherwise the whole path resolves against the **main catalog** — defined only when exactly one
   granted catalog has `is_main` across the principal's roles; ambiguous main ⇒ only qualified names
   resolve (fail closed). Nothing is stored per connection; `USE` under ACL stays denied by the
   statement gate.
3. Effective caps = union over roles of catalog-default caps overridden by per-object caps; `select`
   gates the read path (spec 003), per-verb caps gate DML, as before.
4. Functions (`table|scalar`) resolve by the same catalog rules (unqualified → main catalog);
   `function_gate` consults role rows plus global (`role IS NULL`) rows, falling back to the
   built-in denylist.

Forms map onto the existing rewriter machinery unchanged: `alias` → RENAME, `subquery` →
projection/masks/RLS subquery, `view` → full-SQL subquery; templates keep `acl_claim`/`acl_arg`
markers and the template cache.

### Caching & consistency

- result caches keyed by `policy_version` and the principal's sorted role set: resolved object /
  function policies and gate verdicts (positive and negative), size-capped.
- `policy_version` is re-read at most once per `acl_version_check_interval` ms (extension setting,
  **default 1000**; `0` = check every batch). A version bump invalidates everything.
- One cache-miss = one JOINed query (plus the alias fallback when the object is absent); gate and
  claims lookups are targeted by name/roles — nothing ever loads the whole catalog.
- Admin writes run `BEGIN; …; UPDATE meta policy_version; COMMIT` on a short-lived connection
  (portable upserts as DELETE+INSERT) and force a version re-read on the next resolve.

### Admin functions

New (catalog model): `acl_create_catalog(vcat)`, `acl_add_relation(vcat, vname, phys, cols_csv,
rls)` (form derived: both empty → alias), `acl_add_view(vcat, vname, sql)`,
`acl_add_schema_alias(vcat, alias_path, phys_path)`, `acl_add_table_function(vcat, vname,
sql | target, form)`, `acl_add_scalar(vcat, vname, expr | target, form)`,
`acl_grant_catalog(role, vcat, caps_json, is_main)`, `acl_revoke_catalog(role, vcat)`,
`acl_drop_relation(vcat, vname)`.

Existing `acl_grant_*`/`acl_define_role` become **compatible wrappers**: with the catalog enabled
they write the same content into the implicit catalog `default` and grant it to the role
(`is_main := true`); without a catalog they keep writing to memory. `acl_define_token` stays
memory-only — a deliberate bridge until real JWT verification (007). TOKEN principals therefore
verify in memory while their policy resolves from the catalog.

### Code layout

`acl_policy.hpp/cpp` keeps the `PolicyStore` facade (the seam the rewriter and admin functions see)
plus the in-memory backend; the new `acl_policy_catalog.cpp` implements the catalog backend
(pooled connection, schema init, contract queries, caches). `Principal.role` becomes
`Principal.roles`.

## Enforcement & security

Unchanged invariants: resolvers stay read-only (admin functions write, the resolver never does),
denials throw, unknown/physical names are refused, the rewriter adds no parameters, claim values
bake as constants. New surface: values interpolated into contract SQL are single-quote-escaped;
admin-supplied policy text remains trusted (existing trust model). Ambiguous main catalog fails
closed. Bounded staleness is explicit and configurable (`acl_version_check_interval`).

## Testing

- Unit (`test/sql/acl_catalog.test`): catalog on an ATTACHed in-memory duckdb — `acl_use_db` +
  init, new admin functions, qualified `vcat.…` and main-catalog resolution, schema aliases
  (longest prefix), caps union/override, read/DML gating parity with spec 003, version bump
  invalidation, compatible wrappers writing to `default`, unknown-name denial.
- Existing `test/sql/acl.test` unchanged (memory mode untouched).
- Integration (`test/sql/integration/acl_catalog_postgres.test`): the same flow with the policy
  catalog in the postgres container — schema init through the scanner, enforcement e2e over live
  sources.
- C++ suites unchanged.

## Alternatives considered

- **Role-keyed grants with embedded definitions** (v0.1 of the design) — definition conflicts
  between roles of one principal need priority rules; the catalog model removes the conflict class
  via the primary key.
- **Auto-detected function-driver** — rejected; the function-driver (explicit slot mapping) is
  phase 3 (spec 008).
- **Upserts via ON CONFLICT** — not portable across scanners; DELETE+INSERT in a transaction is.

## Follow-ups

- **Catalog sources to cover with scenarios**: the unit test attaches an in-memory duckdb and the
  integration suite covers PostgreSQL; still to test as policy catalogs — **sqlite**
  (sqlite_scanner is pinned in the submodule config), **mysql** (when the submodule pin re-enables
  mysql_scanner), **SQL Server** (scenario written, skips until the mssql duckdb-main compat build
  lands), and a **persistent duckdb file**.
- 007: JWT verification (issuers, role mappings, EntraID), real multi-role principals.
- 008: function-driver (`acl_use_functions`, explicit slot map) + `ACL ADMIN` management grammar.
- 009: god-mode hardening (`acl.admins`).
