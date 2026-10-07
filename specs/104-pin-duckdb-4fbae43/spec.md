# Spec 104: re-pin duckdb to 4fbae43, duckdb-ext-common to v0.10.0

- **Status**: implemented
- **Date**: 2026-10-07

## Problem

The pin was eb0d9df (spec 100). The head of `v2.0-cyanoptera` is now 4fbae43, 364 commits later,
and the distribution build compiles that head. A pin that stays behind tests a different duckdb from
the one the distribution ships. duckdb-ext-common is at v0.7.1; tresor is already on v0.10.0.

## Design

- **duckdb eb0d9df → 4fbae43** (the head of `v2.0-cyanoptera` on 2026-10-07; no `v2.0.0` tag yet).
  - Nothing in `src/` changes: the API we use did not move.
  - The extension pins under `.github/config/extensions/` are the same, except glue, which we do not
    build. quack stays at 974927a, so `sync.py` regenerates nothing.
- **duckdb-ext-common v0.7.1 → v0.10.0.**
  - It adds the keychain module (spec 010), the OIDC core for services without a shared secret
    (spec 012) and a consumer's HTTP transport for it (spec 013).
  - The contracts (`acl_audit.hpp`, `acl_principal.hpp`, `acl_connection.hpp`) are unchanged, so
    `CONTRACT_VERSION` and ACLC stay as they are.
  - We still compile only the OIDC core's source list.

acl-otel and tresor pin the same duckdb and follow the same day.

## Testing

The whole gate at 4fbae43 / v0.10.0:

- `test/sql/*`, test-cpp, harness, test-flight, test-e2e, test-integration;
- schema-check, clang-format and the thread_local lint.

The distribution build is dispatched on the PR.
