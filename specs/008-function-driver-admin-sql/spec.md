# Spec 008: function-driver policy source + ACL ADMIN management SQL

- **Status**: implemented
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

Phase 3 of the role-aware resolver (design: `design/002-role-aware-resolver`, local). Two things:
(1) the **function-driver** — an external policy source served by registered table-function
callbacks (`acl_use_functions` with an explicit slot map), for platforms that expose their catalog
through C-API UDFs, which never receive filter pushdown; the callback arguments *are* the pushdown.
(2) **Management SQL**: `ACL ADMIN CREATE VIRTUAL CATALOG / CREATE ROLE / CREATE ISSUER / ADD
TABLE|VIEW|SCHEMA|… / GRANT CATALOG / MAP GROUP …` — a human-friendly grammar in our own prefix
scanner, compiled to the existing admin functions.

## Problem

- A platform whose policy lives behind C-API table UDFs cannot use `acl_use_db`: our
  literal-predicate queries push filters into scanners, but UDF/view sources get **no pushdown**, so
  every cache miss would materialize the whole (200K-object) catalog.
- Managing policy through `SELECT acl_grant_catalog(...)` calls works but reads like plumbing;
  admins expect SQL-shaped management statements, deliverable through any door (quack/ADBC).

## Design

### Function-driver (`acl_use_functions`)

```sql
SELECT acl_use_functions('{
  "policy_version":   "my_policy_version",
  "role_catalogs":    "my_role_catalogs",
  "relations":        "my_relations",
  "relation_columns": "my_relation_columns",
  "schema_aliases":   "my_schema_aliases",
  "functions":        "my_functions",
  "object_caps":      "my_object_caps",      -- optional: absent = catalog-default caps only
  "function_gate":    "my_function_gate",    -- optional: absent = built-in denylist
  "issuer":           "my_issuer",           -- optional: absent = no JWT issuers
  "role_mappings":    "my_role_mappings"     -- optional: absent = no external role mapping
}');
```

- **Explicit slot map, no autodetect** (design decision №8): the six core slots are required,
  missing → error at enable; every named function is checked against `duckdb_functions()` and the
  `policy_version` slot is probed immediately — fail closed before switching over.
- **Same resolution SQL, different sources.** The backend keeps the single JOIN-shaped resolution
  of spec 006; only the FROM sources change: a table reference becomes a callback invocation with
  **literal list arguments** (`my_relations(['sales'], ['orders', …])`), and the grants CTE becomes
  a `VALUES` literal built from a prefetched (and cached) `role_catalogs(roles)` call. One
  algorithm, two source sets — nothing to keep in sync.
- Signatures (rows the callbacks must return; extra columns are ignored):
  `policy_version() → (version BIGINT)`; `role_catalogs(roles) → (role, vcat, is_main, caps)`;
  `relations(catalogs, names) → (vcat, vname, form, phys, view_sql, rls)`;
  `relation_columns(catalogs, names) → (vcat, vname, pos, name, expr)`;
  `schema_aliases(catalogs) → (vcat, alias_path, phys_path)`;
  `functions(catalogs, names) → (vcat, vname, kind, form, target, template)`;
  `object_caps(roles, catalogs, names) → (role, vcat, vname, caps)`;
  `function_gate(roles, names) → (role, name, kind, allowed)` ('' role = global);
  `role_claims(roles) → (role, claim, value)` (optional: absent = no role-default claims);
  `issuer(iss) → (issuer, keys_json, audiences, algs, role_claim, claim_map)`;
  `role_mappings(issuer, external_values) → (external_value, role)`.
- The function-driver is **read-only by definition**: every `Catalog*` admin write throws; caches,
  `policy_version` staleness (`acl_version_check_interval`) and the version bump semantics are the
  spec-006 ones. Unmapped JWT role values pass only if `role_catalogs([value])` knows the role.
- `acl_use_db` and `acl_use_functions` are mutually exclusive; the last call wins. Note:
  `acl_version_check_interval`/`acl_jwt_clock_skew` are read at the instance level — change them
  with `SET GLOBAL`.

### Management SQL (`ACL ADMIN …`)

The prefix scanner recognizes management forms after `ACL ADMIN`; anything else stays the existing
native passthrough (so `ACL ADMIN CREATE TABLE …` is still plain DDL). Claimed forms only:

```sql
ACL ADMIN CREATE VIRTUAL CATALOG sales [COMMENT '...'];
ACL ADMIN CREATE ROLE analyst [CLAIMS 'tenant=acme'];
ACL ADMIN CREATE ISSUER 'https://...' KEYS '<jwks|pem>' [AUDIENCES 'a,b'] [ALGS 'RS256']
          [ROLE CLAIM 'groups'] [CLAIM MAP '{"tid": "tenant"}'];
ACL ADMIN ADD TABLE pg.public.orders AS sales.orders [COLUMNS 'id,amount,ssn=NULL']
          [RLS 'tenant = acl_claim(''tenant'')'];
ACL ADMIN ADD VIEW sales.stats AS 'SELECT ...';
ACL ADMIN ADD SCHEMA pg.public AS sales.raw;
ACL ADMIN ADD TABLE FUNCTION sales.report MACRO 'SELECT ... acl_arg(1) ...';
ACL ADMIN ADD TABLE FUNCTION sales.rng ALIAS 'range';
ACL ADMIN ADD SCALAR sales.shout MACRO 'upper(acl_arg(1))';
ACL ADMIN ADD SCALAR sales.lc ALIAS 'lower';
ACL ADMIN GRANT CATALOG sales TO ROLE analyst [CAPS '{"select": true}'] [MAIN];
ACL ADMIN REVOKE CATALOG sales FROM ROLE analyst;
ACL ADMIN MAP GROUP '9f3a-...' FROM ISSUER 'https://...' TO ROLE analyst;
ACL ADMIN MAP CLAIM 'ops' FROM ISSUER 'https://...' TO ROLE operator;
ACL ADMIN DROP RELATION sales.orders;
```

- **No side effects at parse time**: each statement compiles to a synthesized AST —
  `SELECT acl_<fn>(<constants>)` — and flows through the normal bind→execute path into the very
  admin functions that already exist (same transactionality, same store attachment, PREPARE-safe).
  Values are inserted as `ConstantExpression` nodes, never as SQL text.
- A batch after `ACL ADMIN` is either all management statements or all native SQL (the first
  statement decides); mixing is refused with a clear error.
- Grammar keywords (`GRANT`, `ADD`, `MAP`, `CREATE VIRTUAL|ROLE|ISSUER`, `DROP RELATION`) do not
  collide with duckdb statements; unrecognized text after a management keyword is an error, not a
  fallthrough (fail closed — an admin typo must not execute as something else).

## Enforcement & security

The function-driver inherits every invariant: read-only resolvers, fail-closed misses, literal
(escaped) arguments, version-keyed caches. Slot validation fails closed at enable. Management SQL
adds no execution surface: it is a compiler to the already-gated admin functions, argument values
travel as AST constants, and `ACL ADMIN` remains gateway-trusted until spec 009 scopes it.

## Testing

- `test/sql/acl_functions_driver.test` (43 assertions): the contract mocked with SQL table macros
  over VALUES — enforcement end-to-end through callbacks (RLS + role-claims slot, projection, the
  writable alias with caps gating, schema alias, virtual table function, gate rows over the default
  denylist), missing-slot and unknown-function enable errors, read-only admin refusal, and
  version-bump invalidation via the mock (with `SET GLOBAL acl_version_check_interval=0`).
- `test/sql/acl_admin_sql.test` (43 assertions): a catalog built entirely with `ACL ADMIN`
  statements, then enforced (RLS, DML caps, schema alias, vfunc/scalar macros, multi-statement
  management batch); `CREATE ISSUER`/`MAP GROUP` land in `acl.issuers`/`acl.role_mappings`;
  `DROP RELATION`/`REVOKE CATALOG` take effect; `ACL ADMIN CREATE TABLE` passthrough still works;
  typos and management/SQL mixing fail closed.
- Existing suites unchanged.

## Alternatives considered

- **Autodetected callbacks** — rejected earlier (design №8): explicit map, fail closed.
- **Separate C++ resolution path for the function-driver** — two algorithms drifting apart; the
  shared SQL shape with pluggable sources keeps one.
- **Executing management statements inside the parser override** — parse-time side effects break
  PREPARE/EXPLAIN semantics and the statement pipeline; compiling to admin-function calls does not.

## Follow-ups

- 009: `acl.admins` scopes gate both `ACL ADMIN` passthrough and the management grammar.
- The airport-go service (design) is the third source shape: same schema, served over Arrow Flight
  with pushdown; needs no driver changes (it is an `acl_use_db` attach).
