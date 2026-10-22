# Spec 142: ext-common v0.14.0 - PKCE on the device flow

- **Status**: implemented
- **Date**: 2026-10-22

## Summary

duckdb-ext-common v0.14.0 (its spec 017, PR #17; tag f09b0a8, commit ac39cbe) has the OIDC core send PKCE on the
device flow when the issuer's discovery lists `S256` in `code_challenge_methods_supported`. Keycloak always lists it,
then checks the verifier at the poll, even for a client that does not enforce PKCE. Before it, a device login at a
Keycloak client that enforces PKCE failed with "Missing parameter: code_challenge_method" (found by the tresor
session on its test realm). Entra lists nothing and is unchanged.

## Design

- **The pin**: `duckdb-ext-common` v0.13.0 (79467c2) → v0.14.0 (ac39cbe). The contracts (`acl_audit.hpp`,
  `acl_principal.hpp`, `acl_connection.hpp`) are unchanged, so no contract version moves.
- **The one call**: `DevicePoll` takes the verifier as a new required parameter after the device code, on purpose -
  a caller that did not pass it would fail at every such issuer's poll, so it does not compile. acl's quack provider
  secret (spec 061, `FLOW 'device'`) passes `begun.code_verifier`, which `DeviceBegin` sets when it sent a challenge.
- **Together with tresor**: hugr-node compares the OIDC headers of acl and tresor, so both take v0.14.0 (tresor's
  main 5420298, its spec 040).

## Tests

- ext-common's own: the challenge sent when advertised, never when not, the verifier at the poll (its
  `test_oidc_core.cpp`).
- Here: the build with the flight and quack doors (the OIDC core compiled in under acl's namespace), the whole
  `test/sql/*` suite (9845 assertions in 109 files) and `make test-cpp` (28 tests), all green.
