# Spec 099: types under the ACL - names, aliases, enums

- **Status**: implemented (2026-10-05; accepted by the owner 2026-10-02: defaults aliases `base` / enums `keep`; `SET TYPES`; both node settings are cluster-profile items too)
- **Date**: 2026-10-02
- **Follows**: spec 072 (the function gate), spec 098 (the functions listing - the same shape of fix),
  spec 035/026 (listings describe what the role reads; a grant's projection is probed), spec 065 (the
  RENAME and SUBQUERY forms), design/019 (federation), the owner's discussion 2026-10-02

## Summary

What a principal can learn and write about **types**:

1. **No type outside the `system` catalog can be named** under a principal. A user type (`CREATE TYPE`
   in an attached database) is the operator's schema, and its definition can be data - an ENUM's
   labels. Built-in and extension types (`INTEGER`, `JSON`, `GEOMETRY`, an extension's `MSSQL_VARCHAR`)
   live in `system` and stay unrestricted.
2. **`duckdb_types()` answers the `system` catalog's types** only - never another database.
3. **Alias types of extensions are exposed as their base type** (`MSSQL_VARCHAR(50)` → `VARCHAR`), in
   the description and in the data together, by a node setting the virtual table can override.
4. **ENUM columns can be exposed as `VARCHAR`** - same mechanism, same override - because an ENUM's
   description carries its whole domain whatever RLS leaves visible.

## Problem

Probed on the current build (2026-10-02):

- **Type names are not gated.** A principal with no grant on `phys` runs
  `enum_range(NULL::phys.main.client_tier)` → `[acme_platinum, globex_gold]`, `typeof(NULL::phys.main.t)`
  → the same labels, `enum_range(NULL::mood)` for a type of the default database (bare name), and
  `NULL::phys.main.nope` answers "does not exist" - a probe for which types exist.
- **`duckdb_types()` under a `meta` grant** lists every catalog's types with `database_name` - the
  built-ins once per attached database, so the names of every database (`memory, phys, store, temp`)
  and every user ENUM with its labels.
- **An ENUM's domain ignores RLS.** A column `tenant ENUM('acme', 'globex', 'initech')` under a grant
  `RLS (tenant = 'acme')` describes all three - in `information_schema.columns`, in the DDL a quack
  client binds, in `typeof()`, and in the Arrow dictionary of a Flight result.
- **Alias types break quack.** A quack client builds a remote table by **parsing and binding** the
  server's `duckdb_tables().sql` itself (`quack_table.cpp`), so every type named there must exist on
  the client. A user type is expanded by duckdb (`tier` → `ENUM('gold', 'silver')`, `point` →
  `STRUCT(x DOUBLE, y DOUBLE)`, `money` → `DECIMAL(18, 2)` - checked), but an extension's alias type
  (`MSSQL_VARCHAR(n)`: a `VARCHAR` with an alias and `ExtensionTypeInfo`) keeps its name - in the DDL
  and in `information_schema.columns` (`MSSQL_VARCHAR(10)`, checked). **Measured live** (2026-10-02,
  the mssql loadable of the current bump at the same duckdb pin, a node serving a virtual table over
  `(id INTEGER, name MSSQL_VARCHAR(20), tier ENUM(...), s STRUCT(...))`):
  - a quack client **without** the mssql extension fails the **whole ATTACH**, not the one table:
    `Failed to bind remote table while attaching quack catalog "remote" … Type with name MSSQL_VARCHAR
    does not exist` - one aliased column takes the client's entire remote catalog away;
  - a client **with** it loaded attaches and reads every column, the types kept (`MSSQL_VARCHAR(20)`,
    `ENUM('gold', 'silver')`, the struct whole).
- **Description and data must agree for quack.** The client's scan references the server's vectors
  into its output chunk without a cast (`quack_scan.cpp`, `output.Reference(response_chunk)`), typed by
  its catalog. A description that says `VARCHAR` over a stream that carries `ENUM` (or an aliased
  `VARCHAR` - another `LogicalType`) is a vector type mismatch on the client. So a type is changed in
  both or in neither.

## Design

### 1. The type gate

Under a principal, the rewriter walks every position a type is written - `CAST` / `TRY_CAST` / `::`,
the column types of a `CREATE TEMP TABLE` (spec 050), a type nested in `STRUCT` / `LIST` / `MAP` /
`UNION` / `ARRAY`, a typed `NULL` argument - and for each **named** type (`LogicalTypeId::USER`, the
parser's unresolved name):

- qualified with a catalog other than `system` (or a schema of one) - refused
  (`function_denied`-like reason `type_denied`, "type x is not available");
- bare or `system.main.x` - admitted only when the `system` catalog has a type of that name (the
  built-ins and every loaded extension's), and **emitted qualified** `system.main.x`, as spec 072 does
  for functions, so a type of that name in an attached database cannot take it;
- everything else - refused the same way, whether it exists or not (no existence probe).

Anonymous constructors (`ENUM('a', 'b')`, `STRUCT(...)`, `DECIMAL(p, s)`) are built-in syntax and
stay admitted.

A type written as **text** is a type too: `from_json` / `json_transform` and their `_strict` forms
resolve their structure argument as a cast would (found by the review: `enum_range(from_json('null',
'"phys.main.salaries"'))` listed the labels). Under a principal the structure must be a constant
string; it is parsed as JSON, every string leaf parsed as one type, gated, and the structure is
rebuilt with the qualified names (`GateTypeTextArguments`). And a bare name the system catalog lacks
is refused by the gate itself (`PolicyStore::SystemTypeExists`, the system catalog's `duckdb_types()`
cached by name): left to the binder, its "Did you mean `phys.salaries`" named the database that has
it. Table functions with a column-types parameter (`read_csv(types := …)`, `read_json(columns := …)`)
are the file readers' category, never a role's default - a follow-up if one is granted.

### 2. `duckdb_types()`

A metadata surface (spec 035/098 mechanism): substituted before the gate by
`SELECT * FROM system.main.duckdb_types() WHERE database_name = 'system'` - the built-ins and the
extension types once, never another database, no user type, no labels.

### 3. Type exposure: aliases and enums

Two policies, each with a node default and a per-virtual-table override:

| | values | node setting (GLOBAL) | default |
| --- | --- | --- | --- |
| **aliases** - an extension's alias type | `base` (its base type) / `keep` | `acl_alias_types` | `base` |
| **enums** - an ENUM column, user or anonymous | `varchar` / `keep` | `acl_enum_types` | `keep` |

- **The virtual table overrides the node**: `ALTER VIRTUAL TABLE|VIEW c.t SET TYPES (aliases = keep,
  enums = varchar)` / `= default` (a key not written keeps its value; a redefinition keeps both, as it
  keeps the comment). No `CREATE … TYPES` clause: the node's value is the default, and an object
  that differs is said so in one ALTER. Stored on the
  relation (`relations.alias_types`, `relations.enum_types`, NULL = the node's) - schema v19,
  `min_reader` 18 (an older build ignores the columns and keeps the types: it never exposes *less*
  than before, but it can expose more - stated in the migration note).
- **`base` / `varchar` change the description and the data together**: the rewriter adds a cast in
  the read projection (`col::VARCHAR`, `col::<base>`), recursively inside `STRUCT` / `LIST` / `MAP`
  (an ENUM field of a struct becomes a VARCHAR field), and every listing describes the cast type -
  `information_schema.columns`, `duckdb_columns`, the `duckdb_tables().sql` DDL, `DESCRIBE`, the Flight
  schema. The grant projection probe (spec 026) sees the cast like any mask.
- **Writes keep working.** A cast changes only how a row is read. A relation whose read projection is
  renames plus these casts (no mask, no computed column) stays writable: the DML target is the
  physical table as in the RENAME form, and a written string reaches an ENUM column through duckdb's
  implicit cast as it does today. Only a real mask or computed column makes a relation read-only
  (unchanged).
- **`keep` for aliases** is for clients that have the extension (a federation peer with mssql, design/
  019) and want the alias's fidelity (a string length, a collation) - **every** quack client of that
  table must then load it, or its ATTACH fails whole (measured above). Hence `base` by default: the
  rewriter casts `MSSQL_VARCHAR(n)` to `VARCHAR` when it rewrites the read (owner, 2026-10-02).
- **Flight** needs no special case: its Arrow schema is built from the result, so a cast VARCHAR goes
  out as utf8 and never as a dictionary.

### 3a. Measured: a cast in the read keeps the pushdown (SQL Server, 2026-10-05)

The integration SQL Server, the mssql loadable of the current bump, a table of 2 000 rows
`(id INTEGER, name MSSQL_VARCHAR(20), uname MSSQL_NVARCHAR(30))`:

| query | rows the scan returned from SQL Server | result type |
| --- | --- | --- |
| `WHERE name = 'n42'`, plain | 1 | `MSSQL_VARCHAR(20)` |
| the same over `SELECT * REPLACE (CAST(name AS VARCHAR) AS name, …)` | 1 | `VARCHAR` |
| `WHERE uname LIKE 'u4%'` over the cast | 111 | `VARCHAR` |

duckdb pushes the filter through the cast into the scan: the cast belongs in the read projection, no
filter rewriting needed. And the mssql catalog itself reports its columns as `MSSQL_VARCHAR(n)` /
`MSSQL_NVARCHAR(n)` (`information_schema.columns`, `typeof`) - so **every** virtual table over an
mssql source exposes alias types today, and a quack client without mssql cannot ATTACH it: `base` is
what makes mssql behind quack work at all.

### 3b. Where the rewriter learns the types: facts written with the object

Nothing on the query path reads the source (spec 065), so the types are **facts the catalog stores**,
probed where the object is written - as spec 026 probes a grant's projection:

- On every write of the object (`ADD TABLE` / `CREATE VIRTUAL TABLE` / a view / any `ALTER VIRTUAL
  TABLE|VIEW`, `SET TYPES` included) and on `ANALYZE VIRTUAL …` (`acl_refresh_schema`), the object's
  source is bound once (`SELECT * FROM (<phys or view SQL>) WHERE false`, markers baked) and every
  column whose type an exposure policy changes - an extension alias, an ENUM, at any depth of a
  `STRUCT` / `LIST` / `MAP` / `ARRAY` / `UNION` - is stored in `relation_types(vcat, vname, column,
  as_base, as_varchar, as_both)`: the exposed spelling under each of the three non-trivial policy
  pairs (NULL where that pair changes nothing). The facts do not depend on the policy, so changing
  the node's setting needs no rewrite. `ExposedType` (`acl_types.cpp`) is the one rule: an alias
  other than `JSON` becomes its base type, an ENUM becomes `VARCHAR`, nested types are rebuilt.
- The resolver reads the facts with the relation (`LookupRelation`), applies the effective policy
  (the object's own value, else the node's setting) into `TablePolicy::casts`, and the read is
  `ReadFrom()` = `FROM (SELECT * REPLACE (CAST(c AS <type>) AS c, …) FROM <phys> WHERE <rls>) AS
  <phys's leaf name>`: the cast sits **right above the row filter**. A predicate - the object's or a
  grant's - reads the physical values: an ENUM orders by its labels' positions and a VARCHAR
  lexically, so `lvl <= clearance` over the cast values would show a role other rows the moment the
  policy flipped (found by the review: a 'high' document became visible at clearance 'low'). The
  projection and the masks read the exposed values. Writes keep `phys`. A plain alias that needs a
  cast is read through the subquery form and stays writable. A view's casts go above its grant's
  filter (`ApplyGrantPolicy`). The ResolveTable cache key carries the node's two settings.
- Expressions over the exposed type can break (`enum_code(tier)` once it is VARCHAR - the read
  refuses, fail closed) or make a type of their own (`CAST(x AS ENUM(…))` - described as the exposed
  type, read as its own): `acl_check_catalog` probes the declared entries and the grants' masks over
  the cast source and reports `types_incompatible` / `types_mismatch`.
- Every listing passes its `data_type` through `acl_exposed_type(type_text, strip_alias,
  enums_to_varchar)` with the object's effective flags (the `objects` CTE carries them; both false
  for an object with no type facts, which the read does not cast either - after the v19 migration,
  until it is written or `ANALYZE`d, it is described and read as its source has it) - the
  physical row's type, a declared/probed column's, a grant projection's alike - so a mask over an
  ENUM column is described as `VARCHAR` exactly when it reads one. `acl_exposed_type` binds a type by
  name, so it is in the never set (an `acl_*` name). An operator's expression that manufactures an
  ENUM or alias type of its own is described normalized but read as written - `types_mismatch` names
  it, with the cast to write.
- A principal's own `CREATE` registers a record of fixed shape (no comment, no type policy); its facts
  are probed on the store's connection after the statement - inside an explicit transaction the new
  table is not visible there yet, and the object is then read and described uncast until `ANALYZE`.
- `ADD SCHEMA … EXPAND` / `REFRESH` probe every table they record (one bind each, inside the write).
- The source drifts: `acl_check_catalog` reports `types_stale` when the facts no longer match the
  source (or were never probed because the source did not exist yet), with the repair to paste:
  `ANALYZE VIRTUAL TABLE c.t`.
- Not cast: a live schema alias (no stored object to carry facts), a table function, the memory
  store - each exposes the source's types as they are.
- Table functions are out of this spec (their result columns come through `object_columns`): a
  follow-up if an extension type ever reaches one.

### 4. Making the enum domain visible

`acl_check_catalog` gains `enum_domain_exposed`: an ENUM column of an object, under a grant with RLS,
where the effective policy is `keep` - with the repair to paste (`ALTER VIRTUAL TABLE c.t SET TYPES
(enums = varchar)`). The docs say it next to the live-alias paragraph: an ENUM's labels are visible to
anyone who can see the column, whatever RLS says.

Writers: a role that may write an ENUM column learns its labels from duckdb's own conversion error
(`Could not convert string 'x' to ENUM('a', 'b')`) - `varchar` hides the domain from readers, not
from writers (documented in the security model's accepted risks).

## Enforcement & security

- Fail closed: an unknown or non-`system` type name is refused before bind; the refusal reads the same
  whether the type exists (no probe).
- The cast is part of the rewritten statement, like a mask - a principal cannot read the uncast column
  past it; `typeof()` answers the cast type.
- The node setting is GLOBAL and the table's own value the operator's (`manage` on the catalog); a
  principal sets neither (spec 068).

## Testing

- `test/sql/acl_types.test`: the gate (a physical ENUM by qualified and bare name, `enum_range` /
  `typeof` / cast refused; `INTEGER`, `JSON`, anonymous `ENUM(...)` admitted; a same-named user type in
  an attached database cannot shadow a built-in); `duckdb_types()` (only `system`, no labels, any
  `meta`); ENUM exposure (`keep` / `varchar` by node and by table, listings and `typeof` agree, a
  struct with an ENUM field, writes into the ENUM column still work under `varchar`);
  `enum_domain_exposed`.
- `test/sql/acl_cluster_profile.test`: both settings as cluster items; `acl_schema_window.test` at
  build 19.
- **quack e2e** (`test/e2e/door/types.sh`, in `make test-e2e`; the real client): ATTACH a catalog with `STRUCT`, `LIST`, `MAP`, `UNION`, `ENUM`,
  `JSON` columns and read each; with `enums = varchar` the client's catalog and stream agree (no
  mismatch); a table with an alias type ATTACHes from a client without that extension under `base`.
- **Flight**: the Arrow schema of the same table - utf8 under `varchar`, a dictionary under `keep`.
- **mssql alias types**: `test/e2e/door/types.sh` (in `make test-e2e`) serves an mssql table when the
  extension of the pin and SQL Server are there and a quack client WITHOUT mssql reads it under
  `base`; `keep` was checked by hand (2026-10-05: `typeof` answers `MSSQL_VARCHAR(20)`, the DDL names
  it) - it needs a client with mssql, which the e2e does not build.

## Alternatives considered

- **Always cast ENUM to VARCHAR**: rejected as a default - a domain is often harmless (`draft,
  published`), and the setting plus the check make the sensitive case visible (the owner's model:
  make the operator's threat visible rather than decide it for them).
- **Cast the description only**: rejected - the quack client references the server's vectors
  uncast, so description and data must agree.
- **Gate types by a category like functions**: rejected - the built-ins are harmless and universal;
  the line is `system` vs everything else.

## Decisions (owner, 2026-10-02)

1. Defaults: aliases `base` (the rewriter casts `MSSQL_VARCHAR(n)` to `VARCHAR` on read), enums `keep`.
2. The table-level syntax is `SET TYPES (aliases = …, enums = …)`.
3. `acl_alias_types` / `acl_enum_types` are cluster-profile items too (spec 093): one value for the
   cluster, a group's own on its nodes.

## Follow-ups

- Spec 100: fields of structured types per role (paths in `COLUMNS`, compiled to the masks that
  already work: `struct_pack` / `list_transform`).
