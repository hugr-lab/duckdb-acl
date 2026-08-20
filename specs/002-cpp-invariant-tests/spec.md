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

- **Layout** — one scenario file per invariant under `test/cpp/` (`test_acl_params_passthrough.cpp`,
  `test_acl_instance_isolation.cpp`), sharing `acl_test_util.hpp`: check helpers that read
  `GetError()` only after `HasError()`, a column comparator that re-checks the error state around the
  fetch loop, and a per-scenario wrapper so one aborted scenario cannot mask the others. Each file is
  a plain program with its own `main()`, PASS/FAIL output, and a non-zero exit code on failure.
- **Build** — a `test-cpp` Makefile target (style of `mssql-extension`): a pattern rule compiles each
  `test/cpp/test_*.cpp` (discovered by wildcard) with `$(CXX) -std=c++17 -O2 -DNDEBUG` (matching the
  release build, so `D_ASSERT` stays compiled out) into `build/test/`, incrementally. Binaries link
  the **shared `libduckdb`** (rpath'd into `build/release/src`), exactly like duckdb's own unittest:
  it already carries the statically linked extensions — including the scanners of an integration
  build — together with their resolved third-party dependencies, so the link line never tracks
  archives or loader objects. (Hand-assembling static archives was tried first and broke twice: a
  glob swept up the *dummy* extension loader, silently emptying the linked-extension registry, and
  an integration build's ducklake pulled in a CRoaring dependency the list didn't carry.) The target
  does not depend on `release` — CI builds in a container and tests on the host — it guards on the
  built library and says how to build.
- **CI** — `test_release` (what extension-ci-tools' CI invokes) chains `test-cpp` as a prerequisite
  on the platforms that can build and run the binaries (not Windows, not wasm cross-builds).
- **Extension loading** — the generated loader publishes `acl` on the config and the `DuckDB`
  constructor auto-loads linked extensions, so the tests just `LOAD acl` (an idempotent, cwd- and
  artifact-independent load). The loadable `acl.duckdb_extension` is exercised by `test/harness/`.
- **Test content** (ported from the PoC, then extended):
  - *Params passthrough*: a SUBQUERY relation with RLS (`tenant = acl_claim('tenant')`) and a vfunc
    macro with `acl_arg(1)`. Four scenarios: a parameterless `ACL TOKEN` query reports
    `GetParameterCount() == 0` (the pure form of the golden rule); `$1` in the outer WHERE and as the
    vfunc argument each report exactly one parameter and re-`Execute` with a different bound value
    while the baked RLS constant stays fixed; a `?` placeholder (numbered by traversal order, so it
    also catches node duplication/reordering) reports exactly one parameter.
  - *Instance isolation*: instance 1 registers a RENAME grant and a token and resolves both; a fresh
    instance 2 is denied the granted name (`no access to object`) **and** rejects instance 1's token
    (`verification failed` — a process-global token map would be a cross-tenant leak); instance 1
    still resolves both afterwards.

## Enforcement & security

The tests are the enforcement story: they pin the parameter golden rule (no rewriter-added
parameters, user parameters bind normally even inside vfunc arguments, claim values stay baked
constants across re-executions) and the no-process-globals rule (a second instance fails closed on a
name the first instance granted).

## Testing

- `GEN=ninja make test-cpp` — builds and runs both binaries; fails the target on any check. A failed
  run prints the binary's full output; a failed compile prints the compiler's diagnostics directly.
- `build/release/test/unittest test/sql/acl.test` — stays green.

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
