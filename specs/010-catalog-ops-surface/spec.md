# Spec 010: operating the virtual catalog — DROP, metadata, introspection

- **Status**: in progress — part 1 (DROP) implemented; parts 2 (metadata) and 3 (introspection +
  `duckdb_*` substitution) follow as their own PRs against this spec
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

Everything an operator needs to *live with* a virtual catalog rather than only build one: `DROP` with
cascades (so what was created can be cleaned up), stored metadata (comments, column names and types —
including for query-defined views and virtual table functions), `acl_*` introspection functions over
the active policy source, and a substitution of `duckdb_*` / `information_schema` that shows a
principal **only what it may see**.

## Problem

- Nothing can be removed: `DROP RELATION` (spec 008) is the only drop, so catalogs, roles, issuers,
  aliases, functions and mappings accumulate forever.
- Nothing can be inspected: with an attached catalog an admin can `SELECT * FROM aclcat.acl.relations`,
  but that is impossible for the function-driver, and it requires knowing the attach name; there is
  no uniform way to ask "what does this policy source hold?".
- **Metadata leaks today**: `duckdb_tables()` / `duckdb_columns()` are ordinary table functions, so a
  principal's query enumerates the whole *physical* catalog (every attached database), while
  `information_schema.tables` is refused as an unknown virtual name — leaky and tooling-hostile at
  the same time.
- Query-defined objects (views, table-function macros) have no physical counterpart, so their column
  names, types and comments are unknown to any tool.

## Design

### 1. DROP with cascades

```sql
ACL ADMIN DROP VIRTUAL CATALOG sales [CASCADE];   -- definitions always; grants only with CASCADE
ACL ADMIN DROP VIRTUAL TABLE|VIEW sales.orders;   -- aliases of the existing DROP RELATION
ACL ADMIN DROP VIRTUAL SCHEMA sales.raw;
ACL ADMIN DROP VIRTUAL TABLE FUNCTION sales.report;
ACL ADMIN DROP VIRTUAL SCALAR sales.shout;
ACL ADMIN DROP ROLE analyst;                      -- claims, grants, object caps, admin scope, mappings
ACL ADMIN DROP ISSUER 'https://...';              -- its role mappings
ACL ADMIN DROP MAP GROUP '9f3a…' FROM ISSUER '…' TO ROLE analyst;
```

Dropping a catalog removes its own definitions (relations, columns, aliases, functions) always;
role grants pointing at it are removed only with `CASCADE`, otherwise the statement fails and names
the roles that still hold it — an accidental drop should not silently revoke people's access.
Authorization follows the existing provenance rule: a catalog-scoped `manage` drops **inside** its
catalogs; dropping a catalog itself, roles, issuers and mappings needs an unrestricted manage or
passthrough (they are not catalog-specific).

### 2. Metadata: comments, names, types

New optional columns: `relations.comment`, `relation_columns.type` + `.comment`,
`functions.comment`, plus a `functions_columns` table for a table function's result schema.
Three sources, resolved in this order per field:

1. **declared** — what an admin wrote (`COMMENT '…'`, `COLUMNS 'id INT COMMENT …'`);
2. **physical** — for `alias`-form relations and plain (non-expression) projected columns: the
   physical `duckdb_tables()`/`duckdb_columns()` row, read live, so it never goes stale;
3. **probed** — for query-defined objects (`view` form, table-function macros) there is no physical
   row, so the schema is derived by **binding the template at write time** and stored:
   `ADD/ALTER VIEW|TABLE FUNCTION` binds `SELECT * FROM (<sql>) WHERE false` with `acl_claim(…)` and
   `acl_arg(n)` baked to NULL, and persists the resulting names and types. Every change goes through
   us, so the stored schema is written exactly when the definition is.

Consequences of probing on the write path (deliberate):

- **it never costs anything at query time** — introspection is a pure read, no bind, no settings;
- the probe can fail (the source is not attached yet, or a macro's `acl_arg` cannot be NULL) — that
  is not a refusal: the object is stored with "schema unknown" and a flag;
- the physical schema can drift under a stored one, so `acl_refresh_schema(vcat[, vname])` /
  `ACL ADMIN ANALYZE VIRTUAL CATALOG c` re-probes; `alias`-form objects never need it.

### 3. `acl_*` introspection

`acl_catalogs()`, `acl_relations()`, `acl_relation_columns()`, `acl_schema_aliases()`,
`acl_functions()`, `acl_roles()`, `acl_role_claims()`, `acl_grants()`, `acl_object_caps()`,
`acl_admins()`, `acl_issuers()`, `acl_role_mappings()`, `acl_function_gate()`, `acl_describe(vcat,
vname)`, and `acl_status()` (active backend, `policy_version`, staleness interval, which enumeration
is available). They read the **active** source, so they work in all three modes — with one honest
difference:

| mode | enumeration |
| --- | --- |
| memory (dev) | full — the store's own maps |
| attached catalog | full — a SELECT over the source's tables |
| function-driver | only what the platform exposes through optional `list_*` slots (the resolution contract is keyed lookup, so "show me everything" is not expressible without them) |

A missing `list_*` slot makes the corresponding function **throw** ("this policy source does not
expose enumeration for relations") rather than return an empty set: on an admin surface, silence
reads as "nothing is configured", which is a lie an operator would act on.

Gating: these functions administer/expose policy, so the spec-009 rule already denies them in a
principal's query (`acl_*` is refused by the function seam). They are available in the native
context, and a `manage` scope reaches them through the grammar:

```sql
ACL SHOW CATALOGS | RELATIONS IN sales | COLUMNS OF sales.orders | GRANTS FOR ROLE analyst
        | ROLES | ISSUERS | ADMINS | STATUS
```

compiled to the same functions with the scope's catalogs baked in as a filter — same authorization
path as every other management statement, no exit into the native context.

### 4. `duckdb_*` / `information_schema` in the virtual context

In a principal's query these are rewritten into subqueries over the introspection functions with the
principal's roles baked in, so a tool sees exactly its own catalog:

| surface | content |
| --- | --- |
| `duckdb_databases()` | one row per granted catalog |
| `duckdb_schemas()`, `information_schema.schemata` | schema prefixes inside granted catalogs + schema aliases |
| `duckdb_tables()`, `information_schema.tables` | granted relations: `database_name` = catalog, `schema_name` = path prefix, `table_name` = last component |
| `duckdb_views()` | `view`-form relations |
| `duckdb_columns()`, `information_schema.columns` | **the columns the role actually sees** — the projection for subquery form (masked/dropped columns are absent), physical columns for alias form, stored probe results for views/macros |
| `duckdb_functions()` | virtual functions of the granted catalogs |

Rules: an object appears if the role holds any capability on it; **no physical name ever appears**
(`database_name` is the virtual catalog, `sql` is NULL, sizes are NULL/0); a schema alias is
enumerated by reading the physical catalog under its `phys_path` and renaming into the virtual
prefix. Under `ACL ADMIN` / `ACL NATIVE` the real, unfiltered `duckdb_*` is returned — that is what
the native context means. A setting (`acl_virtual_introspection`, on by default) can turn the
substitution off, in which case the metadata surfaces are simply denied rather than leaking.

## Enforcement & security

Introspection is enforcement, not decoration: the substitution filters by the principal's grants
inside the query (not after it), column-level masking survives into `information_schema.columns`, and
physical names/definitions never cross the boundary. The leak that exists today (`duckdb_tables()`
enumerating every attached database for any principal) is closed by the same change — the `acl_*`
deny of spec 009 plus these rewrites.

## Testing

- `acl_drop.test` (61 assertions, **implemented**): build a full catalog (relations, view, alias,
  table function, scalar, grant, issuer, mapping), drop each kind and watch the names stop resolving;
  a missing target is an error, not a silent success; a catalog still granted is refused and names
  the holders (and the refusal changes nothing), `CASCADE` removes definitions and grants together;
  dropping a role or an issuer takes its claims/grants/scope/mappings with it; a catalog-scoped
  `manage` may drop inside its catalog but not the catalog itself (privilege administration) nor
  anything non-catalog-specific; the whole catalog can be emptied to zero rows.
- `acl_introspection.test`: `acl_*` functions in memory and catalog modes, `ACL SHOW` under a
  catalog-scoped manage (only its catalogs), the function-driver's honest error for a missing `list_*`
  slot, `acl_status()`.
- `acl_virtual_catalog.test`: a principal's `duckdb_tables()`/`information_schema.columns` showing
  only granted objects and only visible columns; masked columns absent; no physical names; native
  context still unfiltered; the pre-existing physical-catalog leak refused.
- Metadata: comments and types for alias/subquery/view/macro objects, a probe failure stored as
  "unknown" and repaired by `acl_refresh_schema`.

## Alternatives considered

- **Probing at query time** (first cut): every `information_schema.columns` scan would bind every
  virtual view; the write path already owns every change, so the probe belongs there.
- **Returning empty sets when a source cannot enumerate** — indistinguishable from "nothing
  configured"; an explicit error is the only honest answer on an admin surface.
- **Leaving `duckdb_*` untouched** — keeps a real metadata leak and breaks tooling; denying them
  outright fixes the leak but leaves tools blind.

## Follow-ups

- `SHOW TABLES` / `DESCRIBE` / `PRAGMA table_info` are statement forms the ACL statement gate refuses
  today; map them onto the same rewrite or leave a clear message pointing at `information_schema`.
- Cascade-aware `DROP` for the function-driver (needs `list_*` slots to know what to cascade).
