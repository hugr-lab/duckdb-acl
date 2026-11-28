# Spec 184: ext-common v0.17.0 - the secret_compute contract

- **Status**: implemented
- **Date**: 2026-11-28

## Summary

duckdb-ext-common v0.17.0 (tag c6006f3, commit 37d542e; its spec 020) moves under acl. It adds a neutral contract,
`contracts/secret_compute.hpp`: a secret's storage computes a parameter for the extension that consumes it.
`tresor_audit.hpp` gains a `mint` kind and two reason codes, in comments only.

## Design

- **The pin**: `duckdb-ext-common` v0.16.0 (6a3a3db) → v0.17.0 (37d542e).
- **acl's code**: nothing changes. acl includes neither new nor changed header; `oidc/` is unchanged and no
  contract version moves.
- **Why take it**: hugr-node builds acl, tresor and acl_otel into one extension and compares their copies of
  `oidc/include/*` and `contracts/*` byte for byte. tresor takes v0.17.0 for its computed parameters (tresor spec 048),
  so `tresor_audit.hpp` differs from acl's until acl takes the tag too.

## Tests

The build with the quack door, the whole `test/sql/*` suite and `make test-cpp`, unchanged. CI builds the flight and
quack doors.
