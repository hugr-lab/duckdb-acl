# Spec 116: quoted names

- **Status**: implemented (2026-10-10; accepted by the owner 2026-10-09)
- **Date**: 2026-10-09
- **Author**: Claude (with the owner; issue #197)
- **Follows**: spec 113 (DDL names, refuses a dotted part), spec 112 (lineage names), spec 094 (schema
  window), spec 115 (functions in every held catalog). Before the release (RELEASE-PLAN 4.7).

## Summary

A virtual catalog, schema, table, view, table or scalar function - and a physical name it points at -
may be named the way SQL allows: any case, spaces, special characters, a dot or a quote inside a part
(`"Sales Mart"."Order Items"`, `"Raw Data"`, `"Shout-It"`, `"a.b"`). A name means the same thing in
our grammar, in the policy catalog and to duckdb's binder: read and written with duckdb's own
identifier rules, compared case-insensitively as duckdb's catalog does.

## Problem (probed 2026-10-09, #197)

1. The management grammar reads only `[A-Za-z0-9_]` words joined by `.` (`AdminScanner::Word` /
   `Dotted`, acl_admin_sql.cpp): `CREATE VIRTUAL CATALOG "Sales Mart"` → `expected a catalog name`.
2. Case: every stored key is compared with an exact literal (`r."vname" = Lit(...)`), so `upper.t` misses
   a stored `Upper.T` - while duckdb folds identifiers, and the memory store already compares
   case-insensitively (the two backends disagree).
3. Physical names: `ParsePhysName` splits on `.`, so `phys."Raw Data"."Order Items"` becomes identifiers
   with the quotes inside and the binder quotes them again.
4. Functions: duckdb's transformer lowercases every function name, quoted or not - a stored `Shout-It`
   is never found (a case-insensitive compare is required, not optional).
5. Dots: names are dotted strings everywhere (`VirtualKey`, `relations.vname`, `schemas.path`, the
   listings' `regexp_extract(vname, '^(.*)[.][^.]*$')`); spec 113 refuses a dotted part to stay safe.

## Design

### 1. One name type
`NamePath` (header-only, `src/include/acl_name_path.hpp`): a list of identifier parts.
- read: `FromQualified(QualifiedName)` (a parsed SQL name), `FromKey(text)` (a stored key or a name
  given as text - duckdb's `QualifiedName::ParseComponents`: an unquoted part is anything but `.` and
  `"`, a quoted part `"…"` with `""` escapes, an empty part refused);
- write: `ToKey()` - the **canonical stored key**: parts joined by `.`, a part quoted (`"…"`, `""`
  inside) only when it contains `.` or `"` - the exact inverse of `ParseComponents`; `ToSql()` -
  SQL text through `QualifiedName::ToString` / `SQLIdentifier` (quotes keywords too; never used for
  keys, since duckdb's keyword list changes between versions);
- structure: `Head` / `Rest` / `Parent` / `Leaf`, `Fold()` (lower-cased key for caches);
- SQL fragments, so no ad-hoc regexp remains: `KeyEqSql(a, b)` (case-insensitive), `KeyPrefixSql`,
  `KeyParentSql(expr)`, `KeyLeafSql(expr)` (quote-aware), plus an unquote for display.

### 2. Storage: canonical text keys, no DDL change
Every name column stays text and holds the canonical key. No stored name can contain `.` or `"` today,
so every existing key is already canonical - nothing is rewritten. A stored `phys` value is read with
`FromKey` (an existing `phys."Raw Data"."Order Items"` parses) and new writes normalise it. Rejected:
a LIST path - the policy catalog lives in any attached engine (spec 006), and MySQL / SQL Server have
no arrays.

### 3. Case
Names are stored as written and compared case-insensitively with ONE fold everywhere - ASCII only, as
duckdb's catalog does (`KeyFoldSql` = `translate(x, 'A..Z', 'a..z')` in SQL, `StringUtil::CIEquals` /
`Lower` in C++, the memory store's maps and every cache key) - for catalogs, schema paths, relations,
functions, references and keys. `Ä` and `ä` are two names, as in duckdb. (Review 2026-10-10: SQL's
`lower()` folds Unicode, and two folds gave two answers to "the same name" - a cut by bytes after a
fold that changed a length, and a merge of two objects; see As built.) A name that differs from an
existing sibling only by case is refused where it is written.
Roles, groups, issuers, clients are **values** (claims, mapping targets), not SQL identifiers: the
grammar accepts them quoted, comparison stays exact (as today) - owner, 2026-10-09.

### 4. Grammar
`AdminScanner::Ident()` (a word, or `"…"` with `""`) and `Path()` (idents joined by `.`) replace
`Word` / `Dotted` at every name read (~45 sites: catalog, virtual name, schema path, function, role,
physical path). A single-quoted name keeps its legacy meaning (a whole path, read with `FromKey`); a
double-quoted one is **one identifier**, as in SQL - the old `"pg.public.orders"` reading (a whole
path in double quotes) is dropped: there are no old clients or catalogs to keep (owner, 2026-10-09). The `acl_*` functions read a
name argument with `FromKey` (compatible with every caller today).

### 5. Resolution and the rewriter
`VirtualKey` / `Key` (spec 114) build `NamePath` keys; `ParsePhysName` becomes `QualifiedName::Parse`;
DDL homes (spec 113) concatenate with `NamePath`, so `RequireUndottedParts` is lifted (a spec 113
addendum). The resolver API takes canonical keys; `SplitName` goes; every `= Lit(...)` on a name
becomes `KeyEqSql`. The spec 112/115 `<vcat>.main.<x>` fallback compares `main` case-insensitively.

### 6. Output
Listings (information_schema, duckdb_*, SHOW, Flight RPCs, `acl_function_columns`) answer each
**part unquoted** (`table_schema` = `Raw Data`, `table_name` = `Order Items`); a nested schema keeps
its dotted path, a part with a dot shown quoted in it (`a."b.c"`). Lineage names
(`<vcat>.<schema>.<object>`) use the canonical rule - unquoted unless a part holds `.` or `"`, so the
name stays parseable and equal to our key. Audit object names and messages print the canonical key.
The function-driver slots (spec 008) return canonical keys (documented).

### 7. Migration: schema v20, no DDL
Done properly, with no compatibility to keep (owner, 2026-10-09: no old clients or catalogs exist):
`min_reader_version` = 20 - a build before this spec refuses a v20 catalog (spec 094) rather than
reading quoted keys it does not understand. The step refuses to apply while case-colliding keys exist
(and lists them).

## Enforcement & security

- A name is never two things: canonical keys are unique per path; case-insensitive comparison plus
  the refusal of case siblings at write means one key per object, as duckdb has one entry.
- Prefix matching (`substr(key, 1, len(path)+1) = path || '.'`) stays sound on canonical keys (parts
  are self-delimiting).
- Nothing widens: every resolution site moves to the same comparison; a fallback (`main.`) still only
  applies when the exact name is not stored (spec 115).

## Testing

- C++ invariant test `test_acl_name_path.cpp`: `FromKey`/`ToKey` round trip against `ParseComponents`,
  quote-aware `KeyLeafSql`/`KeyParentSql` evaluated in duckdb over a matrix of names.
- `test/sql/acl_quoted_names.test`, run in catalog and memory mode: `"Sales Mart"`, `"Order Items"`,
  `"Upper"` read as `upper` / `UPPER`, `"a.b"` as one schema beside a path `a.b`, `"x-y"`,
  `"q""uote"`, `c."Raw Data".sub."T"` - catalog, expanded and alias schemas, table, view, table
  function, scalar `"Shout-It"`, references, keys, catalog/schema/object grants with masks; read, DML,
  spec 113 DDL in a quoted home, `DESCRIBE`, `SHOW TABLES`, information_schema, `duckdb_functions`,
  `acl_check_catalog`. Negative: a case sibling refused (each kind), an empty / unterminated quote,
  a quoted name not matching a dotted path, `c.MAIN.f` vs a nested `main.f`, the migration refusing
  collisions, a v19 build refusing a v20 catalog.
- Physical: `phys."Raw Data"."Order Items"` stored either way resolves; a postgres mixed-case table
  (integration).
- Flight e2e (GetTables / include_schema / keys), quack door, lineage names (acl_lineage.test).

## Alternatives considered

- **LIST / separate columns for paths** - no arrays on MySQL / SQL Server; ~14 tables to change.
- **`SQLIdentifier` (keyword-quoting) for keys** - keys would drift with duckdb's keyword list.
- **Case-sensitive like today** - disagrees with duckdb and with the memory store, and functions
  cannot work (the transformer lowercases them).

## Follow-ups

- `ddl` / `export_script` (spec 117) emit names with `NamePath::ToSql()`.

## As built (2026-10-10)

- **One representation**: every vcat / vname / schema path / phys string in C++ is a canonical key
  (`src/include/acl_name_path.hpp`, header-only). Raw parts appear only at the boundaries -
  QualifiedName parts, the grammar's `Ident`, listing output, the lineage scratch's SQL. A catalog is a
  one-part key (`"x.y"` for a catalog holding a dot). Concatenating keys with `.` gives a key; a raw
  part is joined with `ChildKey`. `NamePath::Parts()` returns by value on a temporary (a range-for over
  `FromKey(k).Parts()` dangled and dropped a session's USE schema from a lineage job - found by
  `test_acl_session_use`).
- **Case: canonicalise at write, compare case-insensitively at read** (owner-accepted). Lookups from
  input use `KeyEqSql` / `KeyPrefixSql` (`lower()`); joins between the policy's own tables stay exact,
  which holds because every admin-function name argument first takes the stored spelling
  (`PolicyStore::SpellCatalog` / `SpellName` / `SpellReference`, `CatalogBackend::Spell`): each part
  adopts the spelling a stored name gives it (parent schemas, the object itself). The manage-scope
  check of `AuthorizeMgmt` is case-insensitive for the same reason.
- **Case siblings** (owner-accepted): a NEW name (create / replace; `IF NOT EXISTS` adopts and skips)
  whose leaf differs only by case from ANY stored name of its catalog - relations, functions of either
  kind, schemas, object and schema grants - is refused: one spelling per name in a catalog, stricter
  than per kind (a relation and a function share `role_object_caps` rows by name). Catalogs against
  every catalog column, references among references.
- **Grammar**: `Ident` (a word or `"…"`), `Path`, `Dotted` (= the path's key), `IdentKey` (a catalog),
  `PathName` (virtual/physical; `'…'` = the legacy whole path, read with `FromKey`), `NameValue`
  (issuers, clients, groups, secrets, extensions, source aliases: the old reading), `DottedWords`
  (claim paths). Roles, groups and categories are read with `Ident` and compare exactly. A reference's
  column pair takes a quoted column (`ON ("Order Id" = id)`), which before stored the quotes.
- **Display** (owner-accepted refinement of §6): a one-part schema holding a `.` is listed as its key
  (`"a.b"`), so it never reads as the path `a.b`; every other one-part name unquoted, a path as its key
  (`NamePath::Display` / `FromDisplay`, `KeyDisplaySql` / `KeyFromDisplaySql` - the Flight key RPCs
  rebuild a stored key from the shown columns). Listings compute in key space and convert at the end
  (`named(...)` in acl_metadata_listing.cpp); oids stay computed from keys. `SHOW TABLES FROM`,
  `current_database()` / `current_schema()` answer the shown forms.
- **Repair statements** (owner-accepted) print names in the grammar's form (`ToGrammar`: a plain word
  as it is, any other part double-quoted) - `ToSql` quotes unreserved keywords (`"old"`), which is right
  for the binder and noise for an operator.
- **Physical names**: `ParsePhysName` = `KeyToQualified`; every `FROM <phys>` the writers, validators
  and the maintenance check compose goes through `KeyToSql`. A stored `phys."Raw Data"."Order Items"`
  parses as three parts; new writes store `phys.Raw Data.Order Items`.
- **`c.MAIN.f`** now finds a nested `main.f` (case-insensitive), before the `main` fallback could land
  it on the root `f`; the fallback compares `main` case-insensitively (`MainFallback`, acl_policy.cpp).
- **Spec 113's refusal of a dotted part is lifted** (its addendum): `"sub.t"` is one identifier, so the
  review's finding (a RENAME re-pointing a record at a hidden nested table) cannot recur.
- **Lineage**: a virtual dataset key holds keys; the dataset name is `JoinKeys(vcat, [main.]object)`;
  a physical one quotes its schema/table parts by the same rule.
- **Schema v20** (`schema/migrations/v20.sql`, `-- min_reader: 20`): no DDL; one SELECT that `error()`s
  with the collisions in a deterministic order - per name across the name columns of a catalog, every
  parent level (a recursive CTE), catalogs across every catalog column, references. A v19 build is kept
  out by `min_reader_version` 20 (spec 094's window, pinned by `acl_schema_window.test`).
- **Review fixes (2026-10-10)**, each with a regression test:
  - **one fold** (ASCII, `KeyFoldSql`) in every name comparison, the v20 collision check included -
    `lower()` folded Unicode while C++ and duckdb fold ASCII (`acl_quoted_names.test`: `Öl` / `öl` two
    objects; a grant on `c."ä"` over a stored `c."Ä"` refused as missing, its read refused alike);
  - **a schema alias's tail by parts**: `phys_path + path.substr(alias_path.size())` cut by bytes, and a
    Unicode fold could change a length - `c."straße"._priv.secret` over an alias `c."STRAẞE"` read
    `phys.lake_priv.secret`; the tail is now the written path's parts after the alias's;
  - **fail closed on ambiguity**: LookupRelation, ResolveFunction and LookupSchemaAlias refuse
    (`ambiguous name`) when the winning reading names more than one object - never a union of their
    capabilities and predicates (`acl_quoted_names_driver.test`: a driver answering `Orders` and
    `orders`); a principal's `vs."ä"` beside the operator's `vs."Ä"` and a mask on `c."Ä"` beside
    `c."ä"` stay two objects;
  - `acl_check_catalog`'s `expansion_stale` compares a record's raw leaf with the source's listing
    (tables `"a.b"`, `"q""x"` reported stale before; PRUNE spared them already);
  - repair statements quote a catalog (`ANALYZE VIRTUAL CATALOG "Sales Mart"`) and a role (`TO ROLE
    "Mixed Role"`) in the grammar's form - each pinned by running the emitted text;
  - argument filters (`acl_function_columns`, `acl_references(object)`, `acl_keys(object)`) and
    `SHOW TABLES FROM` compare as names compare;
  - **the audit names one object one way**: a read and a DML target are noted by the policy's
    canonical name (`Sales Mart.Order Items`), however written - which also turns the earlier
    as-written `sales` into `c.sales` (acl_pivot.test updated);
  - the v20 step also refuses a stored name that is no key (`a"b`, `x..y`), and catalog and reference
    collisions are pinned;
  - a message prints a key once (`no access to object "Sales Mart.Order Items"`, not `""…""`);
    `KeyToSql` / `KeyToQualified` refuse text that is no key instead of passing it through as SQL;
  - a reference's column pair took a quoted column as written (fixed in the first pass).
- **Tests added by the review**: case siblings across kinds (a scalar and a schema next to a table,
  the full message), the grant parts of the sibling rule (an object and a schema grant written in
  another case land on the stored spelling), spec 113 RENAME in a quoted home, RLS over a quoted
  column, spec 114 USE `"sales mart"` / USE SCHEMA `"raw data"` (`test_acl_session_use.cpp`), spec 115
  filters, the migration's catalog / reference / unreadable refusals, and a memory-mode section (view,
  table function, mask, one object per name in any case, DESCRIBE; its metadata surfaces stay denied
  - the memory store lists nothing, so "both modes" covers resolution, not listings).
- **Not changed**: spec 072's function keys (engine functions, already lowercased); the function-driver
  slots (spec 008) receive and return keys as stored - a driver comparing exactly misses a differently
  cased name (documented); `acl_cluster.cpp`'s source-alias LIKE patterns already cover canonical keys.
- **Tests**: `test/cpp/test_acl_name_path.cpp` (round trip against `ParseComponents`, the refusals it
  does not make, every SQL fragment evaluated in duckdb over a name matrix);
  `test/sql/acl_quoted_names.test` (memory mode: resolution; catalog mode: every kind, DML, DDL in a quoted home,
  metadata, `acl_check_catalog`, the case-sibling and malformed-name negatives, the migration);
  `test/sql/integration/acl_quoted_names_postgres.test` (a mixed-case postgres schema and table, the
  policy catalog in postgres); Flight e2e (`GetTables` / `include_schema` / primary, imported and
  exported keys over `"Raw Data"."Order Items"`); the quack door e2e (a quoted catalog/schema/view
  through quack's catalog and through the door); lineage names in `acl_lineage.test`. Four existing
  tests that pinned case-sensitive or dot-refusing behaviour were updated (`acl_admin_scopes`,
  `acl_ddl_dbt`, `acl_tool_metadata`, `acl_schema_window`).
