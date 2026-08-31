# Spec 061: the quack OIDC secret provider - CREATE SECRET runs the flow

- **Status**: implemented
- **Date**: 2026-08-31
- **Author**: hugr-lab

## Summary

Design/016 block A1: the duckdb-as-client (quack) tier stops needing hand-carried tokens. quack
already reads a `TYPE quack` secret's `token` field whenever `ATTACH` carries no inline TOKEN; this
adds a second PROVIDER on that existing type - `CREATE SECRET s (TYPE quack, PROVIDER oidc, SCOPE
'quack:host:port', ISSUER '...', CLIENT_ID '...', FLOW 'token'|'client_credentials'|'password'|
'device' ...)` - whose create function runs the configured flow through the OIDC core (spec 060)
and stores the minted access token exactly where quack looks. **quack is unchanged; the node is
unchanged** (acquisition stays client-side, design/016 §0). The flow menu is the admin's policy
(§2): all four are offered, the IdP decides which it accepts.

## Design

- `RegisterQuackOidcProvider` registers a `CreateSecretFunction {type: quack, provider: oidc}`.
  duckdb validates the TYPE at CREATE SECRET, not at registration, so the load order of acl and
  quack does not matter; a CREATE SECRET before quack is loaded is the secret manager's own
  type-lookup refusal.
- Flows: `token` stores the given token verbatim (parity with quack's config provider, one uniform
  surface); `client_credentials` and `password` run their grants; `device` prints the verification
  URI + user code to stderr and blocks the statement on the RFC 8628 poll until approved or the
  IdP's own deadline. Discovery is per-CREATE against the ISSUER; `OAUTH_SCOPE` passes through
  (named so because `SCOPE` is CREATE SECRET's own clause).
- **Every CREATE (OR REPLACE) mints FRESH** - spec 060's obligation #2 honoured by construction:
  the TokenCache is consulted for the REFRESH token only (silent re-mints, device flow included),
  never for an access token, so a token cached past its unknowable validity cannot be served. The
  cache key is issuer|client_id|flow|username (obligation #1: a collision can at worst serve the
  same credential); a spent refresh token is invalidated and the full flow runs instead.
- Raw credentials (`PASSWORD`, `CLIENT_SECRET`) are consumed by the flow and never stored; the
  secret carries the minted token (redacted) plus the visible issuer/client_id/flow/username so
  `duckdb_secrets()` tells an operator what minted it.
- Refresh-at-reconnect: quack re-reads the secret on every new connection, so `CREATE OR REPLACE
  SECRET` is the re-mint lever; the token-resolver seam (per-connect minting inside quack) stays
  the recorded v2 (design/016 §10).

## Enforcement & security

Nothing widens: the provider turns configuration into an IdP-minted token the node then verifies
like any other (specs 007/023); a wrong credential is the IdP's own protocol refusal surfaced
verbatim; the node still never sees a password. The session-binding rule (spec 059) governs what a
minted token's expiry means at the door.

## Testing

`test/cpp/test_acl_oidc_provider.cpp` (make test-cpp), against the spec-060 fake IdP and a real
DuckDB instance with the extension loaded: the pre-quack type-lookup refusal; every flow's mint and
protocol refusal (client_credentials/password/device, missing-FLOW guidance); `duckdb_secrets()`
listing; **the fresh-mint-on-replace rule pinned by the IdP's own counters** (the replace runs
grant_type=refresh_token once and the password never travels again); and - where an ACL_QUACK build
is present - **the full round trip**: `acl_quack_serve`, a provider-minted password-flow secret, and
a TOKEN-less `ATTACH (TYPE quack)` reading exactly the acme slice the minted token names. Without a
quack build the round trip skips, the rest still runs (the test registers the TYPE the way quack
would).

## Found along the way (recorded, not fixed here)

A **pre-existing bug**: a virtual table whose RLS is INLINE on `CREATE VIRTUAL TABLE ... RLS '...'`
(rather than on the grant) breaks quack's attach-time catalog composition - the client fails with
*Failed to create view from SQL string - "NULL"*. Bisected live: grant-borne RLS attaches fine
(either physical home), inline-RLS does not; the NULL originates where the catalog serves
`view_sql` (acl_policy_catalog.cpp's relation lookup). No attach test covered the inline shape.
Follow-up spec material; the provider test uses the grant-borne shape meanwhile.

## The review's findings (applied)

- **The cache key now includes OAUTH_SCOPE**: a refresh request carries no scope and answers with
  the original grant's (RFC 6749 §6), so two configs differing only in scope must never share a
  chain - previously a replace asking for a narrower scope silently received the broader token.
- **Rotation survives**: a refresh response that omits the refresh token (the RFC allows it) now
  carries the old one forward instead of destroying the chain after one replace; the test pins the
  SECOND replace against an IdP that rotates exactly that way, and the scope isolation besides.
- **The chain outlives the access token**: the cache stores only the refresh token, with no expiry
  (its validity is unknowable client-side) and the access token blanked; a genuinely dead chain is
  invalidated where the refresh fails with `invalid_grant` - a transport failure or a caller's own
  `invalid_client` no longer evicts a good chain.
- **The device poll is cancellable**: it checks the querying connection's interrupt between polls
  and sleeps in one-second slices, so Ctrl-C ends the wait instead of the IdP's deadline.
- Documented (docs/clients/quack.md): the stale-stored-token failure mode and its re-mint lever;
  PERSISTENT secrets write the minted token to disk and revive stale; the CREATE SECRET statement
  text itself carries credentials, so it belongs on a local, unlogged connection.

## Follow-ups

- The inline-RLS attach bug above.
- Live Keycloak and **Entra ID** validation of the provider (the user's ask): device and
  client_credentials against login.microsoftonline.com, the runbook's Keycloak section gaining the
  CREATE SECRET example.
- The v2 token-resolver seam in quack (per-connect minting); extraction of the provider into a
  standalone client extension (design/016 §11).
