# Spec 076: the shared repository - the audit contract and the OIDC core move to duckdb-ext-common

- **Status**: implemented
- **Date**: 2026-09-18
- **Author**: hugr-lab

## Summary

What several hugr-lab extensions share and none owns now lives in `hugr-lab/duckdb-ext-common`
(its charter, spec 001 there). This spec is our side of its spec 002: the audit contract
(`acl_audit.hpp`, with `Principal` beside it) is included from the submodule's `contracts/` instead
of `src/include/`, and the OIDC client core (spec 060) is compiled in from the submodule's `oidc/`
under our namespace instead of from `src/oidc/acl_oidc.cpp`. Nothing observable changes: the contract's
layout is the same (version 2, no bump), the OIDC names are the same, every suite passes as it did.
The research is design 075 (local).

## Problem

acl-otel carried the whole of this repository - and its nested duckdb, extension-ci-tools and quack -
as a submodule to compile one header. tresor needs the OIDC core too, and a copy drifts. The contract
belongs to neither producer nor consumer; the core to no one extension.

## Design

- **`.gitmodules`**: `duckdb-ext-common` (no submodules of its own, so `recursive` pulls nothing
  extra), pinned to its tag `v0.1.0` (`v0.2.0` since 2026-09-23, see the addendum).
- **The contract**: `duckdb-ext-common/contracts/` on the include path; `acl_policy.hpp` includes
  `acl_principal.hpp` for `Principal` instead of defining it. Every `#include "acl_audit.hpp"` in
  the sources and tests resolves there unchanged. `Principal` being part of the contract's layout
  is now visible where it applies: a field added there is a `CONTRACT_VERSION` bump.
- **The OIDC core**: `include(duckdb-ext-common/oidc/oidc.cmake)`, its sources appended to
  `EXTENSION_SOURCES`, `DUCKDB_EXT_COMMON_OIDC_NAMESPACE=acl` on both targets (the charter's R13:
  the namespace is the consumer's, so two consumers in one image never share a symbol) and
  `DUCKDB_EXT_COMMON_OIDC_TLS=1` where `ACL_OIDC_TLS` was (the flight build's OpenSSL). The ~25 call
  sites keep saying `duckdb::acl::oidc::...`; the include is `oidc_core.hpp`.
- **What stayed**: the door's auth-discovery document - `DoorAuth`, `FetchQuackAuth`,
  `ParseQuackAuthDocument` - as `src/oidc/acl_quack_auth.{hpp,cpp}` over the module's `HttpGet`
  (the door's, not the IdP's: spec 062/064), used by the quack `PROVIDER oidc` secret; its fuzz
  target `test/fuzz/fuzz_quack_auth_parse.cpp` with the one corpus file (`make fuzz-oidc` keeps
  its name). The core's test (`test_acl_oidc`) and the fuzzer of its three parsers moved with it
  and run in the shared repository's CI; `test_acl_quack_embed` compiles the module from the
  submodule the way the extension does (the Makefile's `OIDC_CORE`).
- **Deleted here**: `src/include/acl_audit.hpp`, `src/include/acl_oidc.hpp`, `src/oidc/acl_oidc.cpp`,
  `test/cpp/test_acl_oidc.cpp`, `test/fuzz/fuzz_oidc_parse.cpp` and the three moved corpus files.

## Enforcement & security

- The contract's layout is unchanged, and acl-otel proves it on its side: its two-loadable contract
  test against this extension built **before** the move and **after** (its spec 010).
- No behaviour changes: the same rewriter, the same doors, the same OIDC code under the same names;
  the whole gate (every suite, the harness, the Flight and door e2e, the sanitized C++ tests, the
  fuzzer) is green without a changed expectation.
- The module is compiled with hidden visibility (its `oidc.cmake`) under our namespace: a co-loaded
  loadable on Linux's flat namespace cannot bind to our copy, the lesson of the embedded quack.

## Testing

The whole gate on the moved code: `test/sql/*`, `make test-cpp` (with `test_acl_quack_embed` on the
module from the submodule), the harness, `make test-flight`, `make test-e2e`, CI's sanitized tests
and `make fuzz-oidc` (now the quack-auth parser). No new test: the change is where the code lives.

## Addendum 2026-09-23: v0.2.0, and the https regression the move made

The move lost TLS. Our own core had tested `ACL_OIDC_TLS`, a macro our CMake defined. The module
documents `DUCKDB_EXT_COMMON_OIDC_TLS`, and our CMake defines that one. But v0.1.0's code still tested
the old name, which nobody defines any more.

From #148 (2026-09-18) to this re-pin, every https request of the OIDC core failed in the flight
build, the one that carries OpenSSL, with "https needs a TLS-enabled build". That covered discovery,
the password handshake (spec 064) and the quack provider secret (spec 061). The tests missed it
because every fake IdP here is http. The paragraph above that says "no new test" was wrong.

- **The fix.** duckdb-ext-common v0.2.0 (its spec 003) tests the documented macro. This re-pin brings
  it. The tag also adds the authorization-code flow with PKCE, which tresor needs, and nothing that
  changes for us. The contract is unchanged (`ACLA` version 2).
- **The regression test.** `test/cpp/test_acl_oidc_provider.cpp` points a provider secret at
  `https://127.0.0.1:1` in a build with the flight door. The error must be the network's refusal,
  never the no-TLS message. It fails on v0.1.0 and passes on v0.2.0.

## Alternatives considered

- **Keep the contract here, let acl-otel keep the submodule**: what the charter was written to end.
- **Vendor the module**: the charter's R11 - never a copy.
- **Narrow `Principal` while moving**: a layout change is a bump; deferred to the contract's move
  onto `hooks/` (the charter's last "Initial contents" row).

## Follow-ups

- Re-pin to each tag of duckdb-ext-common a change here depends on; a contract change is a PR there
  first (R6: the contract is ours to change, in its home).
- `contracts/acl_connection.hpp` when tresor's delegation needs the per-connection state.
