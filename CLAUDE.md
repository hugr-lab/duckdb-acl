# duckdb-acl — Development Guidelines

Role/token-scoped access control for DuckDB, implemented as a **`parser_override`** that rewrites the
query AST **before bind**. A trusted gateway prepends an `ACL` prefix to every query; the extension
verifies the principal, resolves virtual names to physical objects, applies row-level security and
column masking, gates functions, and returns real `SQLStatement`s to the normal
bind → optimize → execute path.

Read **[design/DESIGN.md](design/DESIGN.md)** first — it is the canonical description of the model.

## Technology

- **Language**: C++17 (DuckDB extension standard).
- **DuckDB**: tracks **`main`** (submodule pinned in `.gitmodules`); depends on parser/AST APIs
  (`Identifier`, multi-level `QualifiedName`, `MergeQueryNode`, unified DML query nodes) not yet in a
  stable release. Re-pin to a tag once those land.
- **Dependencies**: none (no vcpkg/OpenSSL).
- **Platforms**: Linux (GCC), macOS (Clang).

## Project structure

```text
src/
  acl_extension.cpp          # the whole rewriter (single TU) + extension entry
  include/acl_extension.hpp  # AclExtension : Extension
test/
  sql/acl.test               # sqllogictest suite (require acl)
  harness/                   # runnable end-to-end demo (demo.sql + run.sh)
design/
  DESIGN.md                  # architecture (canonical)
  research/                  # working research notes (RU) from the PoC phase
  specs/                     # one lightweight spec per feature (see specs/README.md)
```

`src/acl_extension.cpp` is intentionally one translation unit for now: `PolicyStore` (per-instance
state + resolver methods + template cache), `AclRewriter` (the AST walker), the `ACL` prefix parser +
`parser_override` entry, and the admin setup functions. Split into multiple files only when a section
grows enough to warrant it.

## Commands

```sh
git submodule update --init --recursive
GEN=ninja make                      # release build of duckdb + the extension
build/release/test/unittest test/sql/acl.test    # run the suite
GEN=ninja make test                 # same, via the ci-tools target
test/harness/run.sh                 # end-to-end demo against the built extension
```

Build outputs: CLI `build/release/duckdb`, loadable
`build/release/extension/acl/acl.duckdb_extension`, test binary `build/release/test/unittest`.
Enable the override in a session with `SET allow_parser_override_extension='fallback';`.

## Code style

- Follow DuckDB's conventions: tabs for indentation, ≤120 columns, `[u]int(8..64)_t` and `idx_t`,
  `unique_ptr`/`optional_ptr`/`reference`, never raw pointers or `const_cast`, braces always, short
  comments. Run `clang-format` (the repo `.clang-format`) before committing.
- Names: files `snake_case`, types `PascalCase`, functions `PascalCase`, variables `snake_case`.
- Prefer sqllogictest (`test/sql/*.test`) over C++ tests. Every feature lands with tests.

## Key concepts (see DESIGN.md for detail)

- **Two replacement forms**: RENAME (name → physical in place, writable) vs SUBQUERY (wrap a SELECT:
  projection/masks/computed columns/RLS/view SQL, read-only). The resolver picks per object.
- **Markers baked into template copies**: `acl_claim('<name>')` → claim constant; `acl_arg(n)` → n-th
  call argument's AST. Never registered as real functions ⇒ a missed marker fails closed at bind.
- **Golden rule**: the rewriter adds no query parameters — a user's `$1`/`?` is the only parameter.
- **Function gating seam**: `PolicyStore::FunctionAllowed` — denies only data-readers / rights-bypass
  functions, passes the rest. This is where a production role-aware resolver plugs in.
- **State is per-instance**: `PolicyStore` reached via `AclParserInfo` (parser) and `AclScalarInfo`
  (admin functions' `function_info`) — no process globals.

## Admin / setup functions (stubs)

`acl_define_token`, `acl_define_role`, `acl_grant_table`, `acl_grant_view`,
`acl_grant_table_function[,_alias]`, `acl_grant_scalar[,_alias]`, `acl_deny_function`,
`acl_allow_function`. These populate the `PolicyStore`; production replaces them with the read-only
role-aware resolver behind the same seam.

## Working process — per-feature specs

We do **not** run full spec-kit. Instead, each feature gets one lightweight spec under
`design/specs/` (see **[design/specs/README.md](design/specs/README.md)**):

1. Before (or alongside) implementing a feature, write `design/specs/NNNN-slug.md` from
   `design/specs/TEMPLATE.md` — problem, design, enforcement/security, tests, alternatives.
2. Implement with tests; keep the spec updated; set its status to `implemented` when done.
3. Reference the spec in the commit/PR.

Keep specs short and honest. When a decision changes, update the spec or supersede it with a new one.

## Gateway

Deployment invariant: **only the gateway connects to DuckDB.** A reference Arrow Flight SQL gateway
(embedding DuckDB, doing JWT introspection → role/claims, prefixing, token-masking) is a separate repo.
