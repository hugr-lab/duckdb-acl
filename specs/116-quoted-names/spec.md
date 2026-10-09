# Spec 116: quoted names

- **Status**: accepted (by the owner 2026-10-09)
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
Names are stored as written and compared case-insensitively (`lower(a) = lower(b)` in SQL,
`StringUtil::CIEquals` / `Lower` in C++), for catalogs, schema paths, relations, functions, references
and keys - as duckdb's catalog compares. A name that differs from an existing sibling only by case is
refused where it is written (each kind). SQL `lower()` folds Unicode while duckdb folds ASCII: `"Ä"`
and `"ä"` are one name to us - stricter, documented.
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
