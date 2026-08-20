# Spec 010: operating the virtual catalog — DROP, metadata, introspection

- **Status**: implemented — parts 1 (DROP), 2 (metadata), 2b (column renames) and 3 (the `acl_*`
  listings, the closed metadata leak and the filtered `duckdb_*` / `information_schema` substitution)
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

Schema v2 adds `relations.comment`, `functions.comment` and one table for every object's column
schema: `acl.object_columns(vcat, vname, kind, pos, name, type, comment, derived)` — `kind` is
`relation` / `table` / `scalar`, and `derived` says whether the row was bound at write time (and may
therefore be re-derived by `ANALYZE`) or declared explicitly and left alone. A **projection is bound
too**: a masked or computed column (`ssn = NULL`, `total = amount * 2`) has no physical column to
borrow a type from, and its type follows the source's, so it is re-derived like a view's. Migrations run in `acl_use_db(..., init := true)`
(`ALTER TABLE … ADD COLUMN IF NOT EXISTS`), so an existing catalog upgrades in place.
Three sources, resolved in this order per field:

1. **declared** — `ACL ADMIN COMMENT ON VIRTUAL TABLE|VIEW|TABLE FUNCTION|SCALAR v.n [COLUMN c] IS
   '…'` (`acl_comment`), and the projected column names of a subquery-form relation;
2. **physical** — for `alias`-form relations and plain (non-expression) projected columns: the
   physical `duckdb_tables()`/`duckdb_columns()` row, read live, so it never goes stale;
3. **probed** — for query-defined objects (`view` form, table-function macros) there is no physical
   row, so the schema is derived by **binding the template at write time** and stored:
   `ADD/ALTER VIEW|TABLE FUNCTION|SCALAR` binds `SELECT * FROM (<sql>) WHERE false` (a scalar macro
   binds `SELECT (<expr>) AS value WHERE false`) with `acl_claim(…)` and `acl_arg(n)` baked to NULL
   by the rewriter's own marker logic, and persists the resulting names and types. Every change goes
   through us, so the stored schema is written exactly when the definition is. Comments survive a
   definition change; dropping an object takes its schema and comments with it.

Consequences of probing on the write path (deliberate):

- **it never costs anything at query time** — introspection is a pure read, no bind, no settings;
- the probe can fail (the source is not attached yet, or a macro's `acl_arg` cannot be NULL) — that
  is not a refusal: the object is stored with "schema unknown" and a flag;
- the physical schema can drift under a stored one, so `acl_refresh_schema(vcat[, vname])` /
  `ACL ADMIN ANALYZE VIRTUAL CATALOG c` (or one object) re-probes and returns how many objects it
  re-derived; `alias`-form objects never need it, since they read the physical catalog live.

### 2b. Column renames keep a relation writable

Renaming is not restricting, so it must not cost writability (a restriction is a positive list and
stays a read-only subquery, so that a column added physically can never appear by itself). A column
list whose every entry renames one column onto another (`order_id = id, total = amount`) therefore
keeps the **alias** form:

- **reads** go through `SELECT * RENAME (id AS order_id, …) FROM <phys>` — renaming **by name**, so a
  column added to the physical table can never shift an alias onto a different column (the hazard of
  positional `column_name_alias`); columns that were not renamed keep their names;
- **writes** keep the real table and map the names back: the `INSERT` column list, `UPDATE … SET`
  targets and the target's own references in `WHERE`/`RETURNING` are translated virtual → physical;
- naming a **physical** column that the policy renamed away is refused — the virtual relation does
  not have that column any more;
- a renamed relation is refused in DML that has a **second relation in scope** (`UPDATE … FROM`,
  `DELETE … USING`, `MERGE`): an unqualified reference could belong to either side, and guessing
  would silently write the wrong column. Relations without renames are unaffected.

### 3. `acl_*` introspection

`acl_catalogs()`, `acl_relations()`, `acl_relation_columns()`, `acl_schema_aliases()`,
`acl_functions()`, `acl_roles()`, `acl_role_claims()`, `acl_grants()`, `acl_object_caps()`,
`acl_admins()`, `acl_issuers()`, `acl_role_mappings()`, `acl_function_gate()`, `acl_describe(vcat,
vname)`, and `acl_status()` (active backend, `policy_version`, staleness interval, which enumeration
is available). They read the **active** source, so they work in all three modes — with one honest
difference:

| mode | enumeration |
| --- | --- |
| attached catalog | full — a SELECT over the source's tables, one function per listing |
| memory (dev) | none: `acl_status()` answers, the listings refuse. The in-memory store is a dev stub whose contents are the test file above it; an operator surface is for deployments, which use a catalog or a driver |
| function-driver | none today: the resolution contract is keyed lookup, so "show me everything" is not expressible. Optional `list_*` slots would change that |

A source that cannot enumerate makes the listing **throw**, with the reason, rather than return an
empty set: on an admin surface silence reads as "nothing is configured", which is a lie an operator
would act on.

The shape of a listing **follows the source**: the bind step runs the query and takes the column names
and types from its result, so no schema is declared here that could drift from the storage after the
next migration. And an issuer's **keys are absent by construction** — they are not in the projection.
A verification key is often public, but an HS256 one is a shared secret, and neither belongs in
metadata.

Gating: these functions administer/expose policy, so the spec-009 rule already denies them in a
principal's query (`acl_*` is refused by the function seam). They are available in the native
context, and a `manage` scope reaches them through the grammar:

```sql
ACL SHOW CATALOGS | RELATIONS IN sales | COLUMNS OF sales.orders | GRANTS FOR ROLE analyst
        | ROLES | ISSUERS | ADMINS | STATUS
```

compiled to the same functions with the scope's catalogs baked in as a filter — same authorization
path as every other management statement, no exit into the native context.

### 3b. Three surfaces, and the leak closed first

duckdb exposes the same catalog **three ways**, and under a principal they behaved differently:

| surface | before | now |
| --- | --- | --- |
| `duckdb_tables()` (table function) | **every table of every attached database** | refused by the function gate |
| `duckdb_tables` (view of the same name) | refused — an unknown virtual name | unchanged |
| `information_schema.tables` (view) | refused — likewise | unchanged |

The view forms were closed by accident: the rewriter resolves a base table reference as a virtual
name and finds none. The function form went through the function seam, where nothing had named it.
The whole `duckdb_*` / `pragma_*` metadata family is now on the denylist of
`DefaultDeniedFunctions()`, so all three surfaces refuse before the substitution below exists —
tooling stays blind for now, which is the lesser of the two evils while it is being built. The native
context (`ACL NATIVE`, passthrough) and an unprefixed connection are unchanged: the gateway is the
boundary, not this list.

### 3c. What a listing can and cannot say

The listing does not rebuild duckdb's metadata shape by hand: it **joins the physical row and
`REPLACE`s the identity columns** with the virtual ones, so types, nullability and whatever duckdb
adds next stay correct for free. Objects with no physical row — a view, a projection's computed
column — are added through `UNION ALL BY NAME`, which fills the rest with NULL.

That splits the answer honestly:

- an **alias** relation is the physical table under a virtual name, so its listing carries the whole
  shape (renamed columns included);
- a **projection** and a **view** are described by their own stored schema: every column the role
  sees, with the type the write-time probe found — but not the attributes only a physical row has.
  A column missing from a listing breaks a tool; a missing `is_nullable` does not.

The surface names are **reserved**: a virtual object may not be called `duckdb_tables` or
`information_schema.tables`, because the name resolves to the listing and the object would be visible
in metadata yet impossible to select. That is refused when the object is defined rather than
discovered later. The function forms take no arguments, and a call that passes one is refused rather
than answered with something it did not ask for.

A masked column typed as `"NULL"` is duckdb's answer for an untyped NULL — an admin who cares about
what tooling sees writes `ssn = NULL::VARCHAR`.

Everything above is **SQL**, generated per surface and spliced in as a subquery: the filtering, the
join and the union run inside the principal's own query, so their predicates push down and nothing is
materialised in C++. The only C++-side query is the write-time probe, once per definition.

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
- `acl_introspection.test` (60 assertions, **implemented**): the listings returning the policy as the
  operator wrote it (catalogs, relations, schemas, functions, claims, all three grant levels, relation
  columns); `acl_status()` answering in every mode while the listings refuse where a source cannot
  enumerate; an issuer's keys absent from `acl_issuers()` under any column and the secret nowhere in
  the row; and a principal refused on every one of them, including `acl_status()`, while the native
  context reads them.
- `acl_metadata_leak.test` (23 assertions, **implemented**): all three surfaces refused under a
  principal — the table function, the view of the same name and `information_schema` — plus their
  neighbours (`duckdb_columns()`, `duckdb_databases()`, `duckdb_secrets()`, `pragma_table_info`),
  while `ACL NATIVE` under a passthrough scope and an unprefixed connection still enumerate.
- `acl_virtual_catalog.test` (92 assertions, **implemented**): the three surfaces answering with the
  principal's catalog; a hidden column absent from the listing rather than merely unreadable; a
  renamed one listed under its virtual name; a computed and a masked one listed with the probed type;
  a view's probed schema; an alias schema enumerated from the source under the virtual prefix; no
  physical name anywhere; a second role seeing its own catalog; a role granted an explicit `{}`
  seeing nothing at all; and the native context still unfiltered.
- `acl_column_aliases.test` (46 assertions, **implemented**): a pure rename list keeps `form =
  alias`; reads show the virtual names (and untouched columns keep theirs) while the physical name of
  a renamed column is gone; `INSERT`/`UPDATE`/`DELETE` land on the physical columns; writing a
  renamed-away physical name is refused; `UPDATE … FROM` / `MERGE` on a renamed relation are refused
  rather than guessed; a restricting projection stays read-only; and a newly added physical column
  cannot shift an alias.
- `acl_metadata.test` (108 assertions, **implemented**): a view's and a macro's schema derived at
  write time (including templates carrying `acl_claim`/`acl_arg`), a scalar macro's single result
  type, an alias-form function deriving nothing, projected names stored for subquery relations, a
  probe that cannot bind stored as "unknown" and repaired by `acl_refresh_schema` once the source
  exists, drift repaired by `ANALYZE VIRTUAL CATALOG`, comments on objects and columns (with errors
  for unknown targets), comments surviving an `ALTER … SET AS`, schema and comments removed on
  `DROP`, and enforcement unchanged throughout.

## Alternatives considered

- **Probing at query time** (first cut): every `information_schema.columns` scan would bind every
  virtual view; the write path already owns every change, so the probe belongs there.
- **Returning empty sets when a source cannot enumerate** — indistinguishable from "nothing
  configured"; an explicit error is the only honest answer on an admin surface.
- **Leaving `duckdb_*` untouched** — keeps a real metadata leak and breaks tooling; denying them
  outright fixes the leak but leaves tools blind.

## Follow-ups

- A **plain** projected column could keep the rich physical row (join it by name) while only computed
  ones fall back to the stored schema — it would recover `is_nullable` and friends for the common
  case, at the cost of doubling the hairiest branch of the listing SQL.
- `ACL SHOW …` as the grammar form of the listings, so a catalog-scoped manage can read them without
  the native context (the functions exist; only the grammar and the scope filter are missing).
- Enumeration for the function-driver, through optional `list_*` slots.


- `SHOW TABLES` / `DESCRIBE` / `PRAGMA table_info` are statement forms the ACL statement gate refuses
  today; map them onto the same rewrite or leave a clear message pointing at `information_schema`.
- Cascade-aware `DROP` for the function-driver (needs `list_*` slots to know what to cascade).
