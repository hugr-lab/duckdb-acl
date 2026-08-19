# Spec 002: standalone C++ invariant tests (params passthrough, per-instance isolation)

- **Status**: implemented
- **Date**: 2026-08-19
- **Author**: hugr-lab

## Summary

Re-home the two C++ tests that prove invariants sqllogictest cannot express: the parameter golden
rule (the rewriter adds no query parameters — a user's `$1`/`?` is the only one and binds normally)
and per-instance `PolicyStore` isolation (policy registered in one `DatabaseInstance` is invisible to
another). They were written in the PoC duckdb tree (`test/extension/test_acl_rewrite_params.cpp`,
compiled into duckdb's unittest) and are ported here as standalone test binaries, following the
`hugr-lab/mssql-extension` pattern.

## Problem

Spec 001 lists both invariants as proven "in the PoC tree, to be re-homed here". This repo currently
has no coverage for either:

- **Parameter passthrough** needs real prepared-statement binding through the C++ API
  (`Connection::Prepare`, `GetParameterCount`, `Execute(value)`); sqllogictest's `PREPARE`/`EXECUTE`
  goes through a `PrepareStatement` root, which the ACL statement gate denies by design.
- **Instance isolation** needs two `DuckDB` instances in one process; sqllogictest runs one.

Until these run here, a regression (e.g. a rewrite path that introduces a parameter, or a global
sneaking back into the store) would not be caught by `test/sql/acl.test`.

## Design

Standalone test programs, not unittest integration:

- **Layout** — one scenario per file under `test/cpp/`: `test_acl_params_passthrough.cpp` and
  `test_acl_instance_isolation.cpp`. Each is a plain program with its own `main()`, small check
  helpers, PASS/FAIL output, and a non-zero exit code on failure.
- **Build** — a `test-cpp` Makefile target (style of `mssql-extension`): compile each file directly
  with `$(CXX) -std=c++17 -I duckdb/src/include`, linking the already-built static libraries —
  `build/release/extension/acl/libacl_extension.a`, `build/release/src/libduckdb_static.a` (twice,
  for link-order cycles) and every other built `.a` under `build/release/extension` /
  `build/release/third_party`. Binaries land in `build/test/` and run immediately. Depends on
  `release`, so use the same generator as the main build (`GEN=ninja make test-cpp`).
- **Extension loading** — `LOAD 'build/release/extension/acl/acl.duckdb_extension'` (with
  `allow_unsigned_extensions`), falling back to `LOAD acl` — the linked-extension registry inside
  `libduckdb_static.a` knows the name because the library is built with this repo's extension config.
- **Test content** is ported 1:1 from the PoC:
  - *Params passthrough*: a SUBQUERY relation with RLS (`tenant = acl_claim('tenant')`) and a vfunc
    macro with `acl_arg(1)`; `ACL TOKEN` prepared queries with `$1` in the outer WHERE and as the
    vfunc argument each report `GetParameterCount() == 1`; re-`Execute` with a different bound value
    changes the result while the baked RLS constant stays fixed.
  - *Instance isolation*: instance 1 registers a RENAME grant and resolves it; a fresh instance 2
    running the same `ACL ROLE` query is denied with `no access to object`.

## Enforcement & security

The tests are the enforcement story: they pin the parameter golden rule (no rewriter-added
parameters, user parameters bind normally even inside vfunc arguments, claim values stay baked
constants across re-executions) and the no-process-globals rule (a second instance fails closed on a
name the first instance granted).

## Testing

- `GEN=ninja make test-cpp` — builds and runs both binaries; fails the target on any check.
- `build/release/test/unittest test/sql/acl.test` — unchanged, stays green (126 assertions).

## Alternatives considered

- **Compile into duckdb's unittest** (the PoC's `TEST_EXT_OBJECTS` route) — requires patching the
  submodule; rejected.
- **Own CMake test target linking duckdb's `test_helpers`/catch** — works (link-to-later-target is
  legal), but couples us to duckdb's test internals and `BUILD_UNITTESTS`, and diverges from the
  sibling-repo (`mssql-extension`) convention of standalone Makefile-built test binaries.
- **sqllogictest `PREPARE`/`EXECUTE`** — the statement gate denies `PrepareStatement` under `ACL` by
  design, and it could not observe `GetParameterCount()` anyway.

## Follow-ups

- More C++-only scenarios can join `test/cpp/` as needed (e.g. concurrency over one store); keep
  preferring sqllogictest for anything SQL can express.
