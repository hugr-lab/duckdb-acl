# Spec 161: ext-common v0.16.0 - a client assertion's type

- **Status**: implemented
- **Date**: 2026-11-13

## Summary

duckdb-ext-common v0.16.0 (tag d812317, commit 6a3a3db; its specs 018 and 019) moves under acl together with tresor.

- **Spec 019.** The OIDC core's `ClientAuth` gains `assertion_type`, the URN a presented assertion is sent as. When
  empty it is RFC 7523's jwt-bearer, as before. Keycloak's SPIFFE authentication wants `…:jwt-spiffe` for a JWT-SVID.
- **Spec 018.** A wasm build compiles the core without its built-in client. Native builds are unchanged.

## Design

- **The pin**: `duckdb-ext-common` v0.14.0 (ac39cbe) → v0.16.0 (6a3a3db). v0.15.0 changed no header. The contracts
  (`acl_audit.hpp`, `acl_principal.hpp`, `acl_connection.hpp`) are unchanged, so no contract version moves.
- **acl's code**: nothing changes. acl presents no assertion; the new member is the last one and defaults to empty.
- **Together with tresor**: hugr-node compares the OIDC headers of acl and tresor byte for byte, so both take
  v0.16.0 (tresor #84; ext-common's compatibility rows, its #23).

## Tests

The build with the flight and quack doors (the OIDC core compiled in under acl's namespace), the whole `test/sql/*`
suite and `make test-cpp`, unchanged.
