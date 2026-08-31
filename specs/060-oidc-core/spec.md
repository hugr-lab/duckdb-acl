# Spec 060: the OIDC client core - acquisition primitives, shared

- **Status**: implemented
- **Date**: 2026-08-31
- **Author**: hugr-lab

## Summary

The token-acquisition design (design/016, settled with the user) needs the same primitives in two
places: the quack secret provider (`CREATE SECRET (TYPE quack, PROVIDER oidc, ...)`, block A1) and
the Flight door's admin-enabled password handshake (block B3). This is that shared core, one module:
endpoint **discovery** (RFC 8414 `/.well-known/openid-configuration`, with the issuer-match check),
the POST **flows** - `client_credentials`, `password`, `refresh_token`, and the **device flow**
(RFC 8628: begin + poll honouring `authorization_pending`/`slow_down`) - and a **token cache** with
a refresh margin. Generalised from `hugr-lab/mssql-extension`'s Azure implementation (its endpoint
constants become discovered URLs); parsing is the bundled yyjson rather than string scanning.

## Problem

Every acquiring layer would otherwise reimplement HTTP, form encoding, the token-response contract,
RFC 8628's poll discipline and cache invalidation - and drift. mssql-extension proves the whole set
works on duckdb's bundled httplib with no SDK; what it lacks is generality (Azure-only endpoints)
and a shared home.

## Design

- `src/oidc/acl_oidc.cpp` + `src/include/acl_oidc.hpp`, namespace `duckdb::acl::oidc`.
  **Deliberately duckdb-free** (std + bundled yyjson + bundled httplib in the one TU): a standalone
  test links the module directly, and nothing about it can entangle the node's verification path.
- **The node never calls it.** Verification (specs 007/023) stays what it is; this module only ever
  runs in client-side roles (the secret provider) or the door's admin-enabled handshake exchange -
  the invariant of design/016 §0 in code form.
- **HTTP**: the single-TU discipline mssql-extension uses - with `ACL_OIDC_TLS` (defined exactly
  when the flight door is built, whose vcpkg tree carries OpenSSL) httplib compiles with
  `CPPHTTPLIB_OPENSSL_SUPPORT` into the `duckdb_httplib_openssl` namespace, no ODR overlap with the
  core's plain copy; https on a build without it is a *named* transport error, never a silent
  downgrade. Certificate verification is on for https.
- **Discovery refuses a lying document**: the advertised `issuer` must equal the one asked about
  (RFC 8414) - adopting a different one would let a compromised document redirect every flow.
- **The token-response contract in one place**: 2xx with `access_token` is a grant (expiry becomes
  absolute `expires_at`); anything else surfaces the protocol's `error`/`error_description` plus the
  machine `error_code` the device poll dispatches on.
- **Device poll**: `authorization_pending` waits the interval, `slow_down` adds 5s (§3.5), any other
  error returns, and a deadline bounds the whole affair; interval 0 polls without sleeping, which is
  what makes the flow testable.
- **TokenCache**: keyed (owner pointer, caller key), served only with more than `margin_seconds` of
  life left, stale rows erased on read - mssql's cache, generalised, refresh tokens carried
  alongside.

## Enforcement & security

- The module holds no policy and grants nothing: it turns configuration and credentials into an
  IdP-minted token, which the node then verifies like any other (nothing here can mint one the node
  would trust wrongly).
- Passwords and client secrets pass through POST bodies to the issuer only - never logged, never
  stored; the cache stores only what the issuer returned.
- Fail-closed edges: unsupported URL schemes, https without TLS, discovery mismatch, 2xx without a
  token - each is a named error, not a fallback.

## Testing

`test/cpp/test_acl_oidc.cpp` (make test-cpp) runs the core against a **fake IdP served in-process**
by the bundled httplib: discovery + the issuer-mismatch refusal; client_credentials grant and the
protocol's own `invalid_client` refusal; password grant with refresh_token round trip and
`invalid_grant`; the device flow riding out two `authorization_pending` answers before the grant
(zero-interval, no sleeps) and `access_denied` for an unknown code; the cache's margin, stale-read
erasure and invalidation. No network, no live IdP needed - the live Keycloak leg arrives with the
consumers (A1/B3).

## Alternatives considered

- **duckdb's FileSystem (httpfs) as the transport** - it is GET-only (fine for JWKS, spec 023), and
  token endpoints need POST; httplib is already bundled and proven by mssql-extension.
- **String-scanning JSON** (mssql's parser) - replaced with the bundled yyjson; a token response is
  attacker-influenced input and deserves a real parser.

## Follow-ups

- Block A1: the quack secret provider consumes this (`FLOW token|client_credentials|device|password`).
- Block B3: the door's admin-enabled password handshake consumes `PasswordGrant`.
- Auth-code+PKCE stays with the drivers (a browser is a client-side affair, design/016 §2).
