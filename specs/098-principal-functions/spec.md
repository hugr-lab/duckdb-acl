# Spec 098: a principal's functions - `duckdb_functions()` answers what the principal may call

- **Status**: implemented (owner, 2026-10-02: Q1 listed without database/schema, Q2 a follow-up listing)
- **Date**: 2026-10-02
- **Follows**: spec 072 (the function gate: categories, grants by name, the never set), spec 035 (the
  table surfaces answered as the principal's own), spec 022/048 (`acl_references` / `acl_keys`: a
  listing substituted before the gate), design/019 §6 (federation: pushdown must know what the remote
  allows), specs/BACKLOG.md ("A principal's functions surface")

## Summary

Under a principal, `duckdb_functions()` answers **the functions this principal may call** - today it
is refused, or with the `meta` category the whole engine's listing: the engine's functions the function gate admits for its roles, and the virtual
functions (table functions and scalars) of its virtual catalogs - with their parameters and comments.
Nothing it may not call appears, and nothing in a row names a physical object.

Two readers need it:

- **An agent or a person browsing the catalog.** A virtual table function is callable today but
  appears in no listing - not a table, not a view, and not in `duckdb_functions()` - so nobody can
  learn it exists or what it takes (the backlog's oldest surface gap, specs 035/046).
- **Federation** (design/019): platform A pushes parts of a query to platform B as SQL text, and
  duckdb's `RemoteExecute` cannot decline, so A must decide *before* sending whether B lets A's role
  call every function in it. A reads B's `duckdb_functions()` as its role and vetoes the rest.

## Problem

- `duckdb_functions()` is a member of the seed's `meta` category (`src/acl_function_seed.hpp`). A role
  without `meta` is refused it; **a role granted `meta` gets the whole engine's listing** - functions
  it cannot call (the never set, denied and uncategorized ones) and the `macro_definition` of every
  macro in every attached catalog, which names physical objects. Both are wrong: the first hides what
  the principal may call, the second shows what spec 052/073 keep out of reach. After this spec the
  `meta` grant no longer matters for this surface: the substitution answers before the gate.
- `acl_function_status([role])` answers the question but is the operator's (an `acl_*` function).
- duckdb has no `information_schema.routines` / `parameters`; `duckdb_functions()` (and its view
  forms) is the one surface tools and drivers read.

## Design

### 1. The surface

`FROM duckdb_functions()` - bare or qualified, and the bare name `FROM duckdb_functions` (duckdb has
no such view at the pin; under ACL the name answers too) - under a principal is replaced, like spec
035's table surfaces, by a subquery with **the same columns** as duckdb's at the pin, holding:

**a) Engine functions the gate admits.** Every row of the engine's own `duckdb_functions()` whose key
`(database, schema, name, kind)` the spec 072 model admits for the principal's roles - a category
granted to one of them or to every role, or a grant by name, no deny anywhere, not in the never set.
The decision is **the gate's own model** (`FunctionCategoryModel`, built when the policy loads), never
a SQL re-implementation of its rules - so the listing and the gate cannot disagree. All overloads of
an admitted key are listed (the gate admits by key, not by signature).

**b) The virtual functions a call of the principal reaches.** The rewriter resolves a function call by
its bare name, in the principal's one MAIN catalog - so the candidates are the flat names of that
catalog (another granted catalog's functions, a nested virtual schema's, or two MAIN catalogs: not
reachable, not listed), and each is then resolved **the way a call is** (`ResolveTableFunction` /
`ResolveScalarFunction`) and kept only with `select` (spec 012: a call is a read) - a function whose
call that resolution refuses (a scalar under a grant that carries a predicate or columns) is left out,
never the whole listing with it. A virtual function also takes the bare call of every engine function
of its name and kind (virtual functions resolve first), so those engine rows leave (a). One row each: `database_name` = the virtual
catalog, `schema_name` = its virtual schema (`main` when flat), `function_type` = `table` / `scalar`,
`parameters` / `parameter_types` from `functions.params`, `return_type` for a scalar from its declared
result column, `comment` from the catalog. A virtual function is a template over physical objects, so
its row carries **no definition**.

### 2. What a row never carries

- **`macro_definition`**: `NULL` on every row except the `system` catalog's own built-in macros (the
  engine's, the same on every node). A virtual function's template and a macro in an attached catalog
  both name physical objects.
- **`database_oid`, `function_oid`**: on a virtual row, the oid every surface gives a virtual object -
  derived from the virtual name, unrelated to any physical catalog (spec 035's addendum: quack reads
  oids as int64 and cannot take NULL); on an engine row outside `system`, `NULL`; kept on `system` rows.
- **Another role's view**: rows are computed from the principal's roles only; no category name of the
  policy appears (`categories` is duckdb's own column, its built-in categories).
- **Physical-catalog functions** admitted by a grant by name (spec 072 allows `db.schema.f` for a macro
  in an attached database): listed by name and signature only (decision 1) - no database, schema,
  definition, oid, description, comment, tags or examples (the operator's prose can name physical
  objects too) - and **only when the bare name reaches it**: a macro named like a builtin (the builtin
  takes the bare call) or tied with another candidate is not listed, since the listing cannot give the
  qualification it would need.

### 3. Mechanism

- The rewriter recognises `duckdb_functions()` / `duckdb_functions` in a principal's FROM and
  substitutes it **before** the function gate (as `acl_references` is), so the principal never calls
  the engine's function directly.
- The admitted set of (a) is enumerated at rewrite time **from the model alone**
  (`FunctionCategoryModel::AdmittedKeys`: every candidate key - category members and keys granted by
  name - judged by the same `Judge` a call gets, the never set dropped), without reading the engine
  or the source on the query path. It is carried into the substituted subquery **as data the
  rewriter writes, never as a parameter** (the golden rule): a constant list of admitted keys the
  subquery filters `system.main.duckdb_functions()` by. A key the node has no function for simply
  matches nothing.
- (b) is `CatalogBackend::VisibleFunctions` - the virtual functions on a catalog the principal holds a
  grant on that is not an explicit nothing (`FunctionVisibleExpr`, the visibility a call resolves
  with) - parameters parsed from the stored list text at depth 0 (`DECIMAL(10, 2)` stays one type).
- Memory mode and the function-driver source answer (a) from their model; (b) is the catalog's only
  (the memory store and a function driver enumerate no virtual functions).
- The substitution matches the table function's own name, so `system.main.duckdb_functions()` and
  `main.duckdb_functions()` are substituted too - the forms a `meta` grant used to answer in full.

### 4. Federation's use (design/019)

Platform A's `hugr` catalog reads `SELECT function_name, function_type FROM duckdb_functions()` on
platform B as A's role, once per connection pool and again at B's next policy version (or a TTL), and
its `SupportsPushdown` vetoes an expression calling anything outside that set. The listing is the
contract; nothing federation-specific lands in acl.

## Enforcement & security

- **The listing never widens the gate**: an engine function appears iff the model admits its key (the
  same `Judge` a call gets) and, outside `system`, its bare name reaches it; a virtual function appears
  iff a call by that name resolves to it with `select`. The parity test compares the listing with
  `acl_function_status` (the same model - it catches an enumeration or filtering slip, not a model
  bug), and the listed virtual functions are called, the unlisted ones refused.
- **Never set, denied, uncategorized** - absent, whatever the categories say.
- **No physical name**: no definition outside the `system` catalog, no physical database in a virtual
  row; the listing is a projection the rewriter builds, so its own text is not the principal's.
- **Golden rule**: the admitted keys are constants the rewriter writes; no parameter is added.
- **Fail closed**: a policy source that cannot answer refuses the listing (`unavailable`), as every
  listing does.
- What a principal learns - which functions it may call - is what calling them would tell it anyway.

## Known limitations

- **The engine half scans every attached catalog.** `system.main.duckdb_functions()` enumerates the
  functions of every attached database (a scanner catalog included) before the filter; an unreachable
  remote catalog fails the listing, and its error text reaches the principal. The table listings
  (spec 035) have the same exposure through `information_schema.columns`; a fix belongs to both.
- **Cost**: the admitted keys are a constant list of ~1-3 thousand string keys, composed per statement
  that names the surface (~1-10 ms of rewrite, ~20 ms to run against ~10 ms for the engine's own
  listing - a row-value IN over the same keys bound ~4x slower), parsed outside the template cache so
  it never evicts relation templates. A statement that does not name it pays nothing. The key joins
  its parts with `chr(31)`: a function name carrying that character (only an operator can create one)
  could match another key - accepted for the speed.
- **A scalar declared without parameters** (`ADD SCALAR c.f MACRO 'upper(acl_arg(1))'`) lists
  `parameters = []` though it takes one argument - the declaration is the contract; declare them.
- **Not listed**: acl's own substituted surfaces (`acl_keys()`, `acl_references()`), and in memory mode
  the legacy virtual scalars/table functions (the memory store enumerates none).
- **Reserved name**: a virtual object can no longer be created as `duckdb_functions`
  (`RequireNotReserved`); one created before this spec is shadowed in FROM (a virtual table function of
  that name still wins the function form - the function path resolves virtual functions first).
- **Seen, not this spec's** (in the backlog): a virtual function call ignores the qualifier written
  (`c.main.shout()` reaches the MAIN catalog's `shout`); `duckdb_types()` under a `meta` grant names
  attached databases.

## Testing

- `test/sql/acl_principal_functions.test`:
  - **parity**: the distinct system keys the principal lists equal the ones `acl_function_status(role)`
    admits (two queries under one result label - proven to fail on a single missing key);
  - a category granted to every role (`base`) is listed, one not granted (`readers`) is not until it
    is; a deny removes one (deny wins over the every-role grant); a grant by name adds a macro of an
    attached catalog, listed with no database, schema or definition; the never set never appears;
  - `function_name` / `function_type` / `parameters` of a virtual table function and a virtual scalar
    of its catalog, with the comment; not another catalog's; `macro_definition` NULL on every row
    outside `system`;
  - virtual rows are callable as listed; a non-MAIN catalog's function, a nested schema's and an
    insert-only grant's are not listed (and the call is refused); a shadowed physical macro is not
    listed; a parameter list with a doubled quote, no type and a default is split right;
  - the bare name `FROM duckdb_functions`, a column alias list, and the qualified
    `system.main.duckdb_functions()` under a `meta` grant (no `acl_*`, no physical definition);
  - the operator (bare, unprefixed) still sees the engine's own listing.
- Memory mode: parity with `acl_function_status` and a deny, for (a).

## Alternatives considered

- **A new `acl_functions()` listing** instead of `duckdb_functions()`: rejected as the primary surface -
  tools, drivers and agents already read `duckdb_functions()`; spec 035 made the same choice for
  tables. (`acl_function_status` stays the operator's.)
- **Re-implementing the gate's rules in SQL over `function_categories` / `function_grants`**: rejected
  - two implementations of "deny wins, `''` is every role, the never set" would drift.
- **Listing every engine function and refusing at call time**: rejected - it advertises what the
  principal cannot use, and the federation veto needs exactly the admitted set.

## Decisions (owner, 2026-10-02)

1. **Functions in attached (physical) catalogs admitted by a grant by name** are listed, with
   `database_name` / `schema_name` `NULL` and no definition: the principal may call them, so it finds
   them; the listing never names the physical database.
2. **Result columns of a virtual table function**: a follow-up listing `acl_function_columns([name])`,
   substituted the same way - `duckdb_functions()` keeps duckdb's shape.
