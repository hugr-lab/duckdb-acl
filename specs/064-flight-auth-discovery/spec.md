# Spec 064: the Flight door's auth discovery + IdP-gated password handshake (Block B)

- **Status**: implemented
- **Date**: 2026-09-01
- **Author**: hugr-lab

## Summary

design/016 Block B, the **node side** of "how a Flight SQL client authenticates without a human
pasting a JWT". The client tooling — a custom JDBC driver, an `acl-login` agent, a Power BI connector
— lives in separate repos (design/016 §3); what the MIT node owes them is two things the Flight door
did not have:

- **B2 — discovery.** The door advertises, unauthenticated, the issuers it trusts, each issuer's
  OAuth client_id, and the endpoints the IdP's own OIDC discovery names — so a driver knows *where*
  to authenticate and *how*. The Flight analog of the quack door's `GET /.well-known/quack-auth`
  (spec 062/063), answered over the **Handshake RPC** (payload `discover-auth`), because that is the
  protocol's own unauthenticated pre-auth exchange and `FlightSqlServerBase` seals `DoAction` final.
- **B3 — the password handshake, gated by the IdP.** For a *vanilla* Flight SQL client (stock Arrow
  Flight JDBC or ADBC, only Username/Password fields, no custom driver), a **BasicAuth Handshake**
  becomes the OAuth password grant (ROPC), run by the node against the issuer's token endpoint as
  the `client_id` the admin put on the issuer. The token the IdP answers is **verified offline
  exactly like any Bearer**, and handed back as the connection's bearer — every later call takes the
  unchanged per-call path. The node carries **no flow toggle of its own**: an IdP that permits ROPC
  answers with a token, one that does not answers `unsupported_grant_type`/`invalid_grant`, and that
  refusal is surfaced as the handshake's answer.

B1 (spec 058's no-op handshake — the server-side prerequisite that lets a header-Bearer client
connect) is unchanged: a payload-less, header-less handshake still succeeds and gates nothing,
because the per-call `authorization: Bearer` header remains the real gate.

## Problem

The door verifies an `authorization: Bearer <jwt>` on every call (spec 045), and that was the whole
of its auth. A client that already holds a token works; a client that does not had no way to (a)
learn which IdP to go to, or (b) get a token from stock Username/Password fields. quack got both
through its server's discovery + provider (specs 061–063); the Flight door had neither.

## Design

### The issuer carries its OAuth client (schema v12)

`client_id` and `client_secret` live on the issuer — the same app registration whose tokens the
node already verifies. `acl_define_issuer(..., jwks_uri[, client_id[, client_secret]])`;
`ACL ADMIN CREATE ISSUER ... [CLIENT ID '<id>' [CLIENT SECRET '<secret>']]`;
`ALTER ISSUER '<iss>' SET CLIENT ID|CLIENT SECRET '<value>'`. A secret without an id is refused
where written; clearing the id clears the secret with it. `acl_issuers()` lists `client_id` (a
public identifier, printed in every SPA) and **never** the secret. Policy catalogs migrate with
`schema/migrations/v12.sql`.

### B2 — discovery over the Handshake

The door's own `ServerAuthHandler` (replacing arrow's `NoOpAuthHandler`) reads the handshake
payload: empty = the spec-058 no-op; `discover-auth` = the discovery document as JSON —

```json
{"issuers":[{"issuer":"https://idp/","client_id":"door-app",
             "token_endpoint":"https://idp/token",
             "device_authorization_endpoint":"https://idp/device"}]}
```

Issuers come from the live policy per request; each issuer's endpoints from
`oidc::Discover` (spec 060), cached process-wide (public metadata keyed by issuer URL; 300 s, a
failure 30 s — an unauthenticated caller must not turn a dead IdP into a fresh network wait each
probe). An unreachable IdP leaves its issuer named, endpoint-less. A
`device_authorization_endpoint`'s presence tells a driver device flow exists — the IdP's own
discovery says what the IdP supports; ours only relays it.

### B3 — the password handshake

A server middleware watches the Handshake for `authorization: Basic`. When present: refuse at once
on a cleartext door (a password on a readable wire is the one thing worse than the node seeing it);
otherwise walk the issuers that carry a `client_id` (one with none cannot do ROPC and is skipped) —
`oidc::Discover` + `oidc::PasswordGrant` (spec 060), verify the returned access token through the
same `VerifyPrincipal` every Bearer takes, and on success answer the handshake with
`authorization: Bearer <access_token>` in the response headers — the place stock JDBC, ADBC and
pyarrow's `authenticate_basic_token` all read it from. The bearer **is the IdP's token**, not a
credential of ours: every subsequent call verifies it offline on the unchanged path, sessions stay
cookie-driven (spec 050), and expiry behaves as for any bearer. The password is used once and is
neither logged nor stored.

## Enforcement & security

- **The IdP is the gate, not a setting of ours** (user, 2026-09-01). The node attempts the grant
  only from a BasicAuth handshake; whether it succeeds is the org's IdP policy, exactly where the
  ROPC decision already lives. The resulting token is still verified offline — the node trusts its
  own verification, never the password.
- **Discovery leaks nothing private** — issuer URLs, a public client_id, and the endpoints the
  IdP's own `.well-known` publishes. Unauthenticated by design.
- **TLS-only by refusal**: the cleartext door refuses the password before anything reads it.
- The plain Bearer path, the cookie sessions, and every per-call gate are untouched.

## Tests

`test/e2e/flight/auth.sh` — a fake IdP (stdlib python, sharing no code with the door) serves
discovery + the grant; asserts: discovery answers unauthenticated from the live policy (issuer,
client_id, token_endpoint, device endpoint; no secret field); a BasicAuth handshake earns exactly
the tenant's RLS slice; a wrong password and an ROPC-off IdP surface the IdP's refusal; a cleartext
door refuses by name; the plain bearer path is unchanged. `test/sql/acl_issuer_client.test` — the
credential surface: both SQL forms, ALTER, secret-without-id refusals, `acl_issuers()` shows the id
and never the secret, and the catalog round-trip keeps it.

## Alternatives considered

- **DoAction("discover-auth") for discovery**: the natural RPC, but `FlightSqlServerBase` seals
  `DoAction`/`ListActions` `final` with no custom-action hook — an unknown action never reaches us.
  The Handshake is the protocol's own unauthenticated pre-auth exchange, and doubles as where the
  password flow already lives.
- **A door-minted session token as the handshake's bearer**: a second bearer kind with its own
  lifetime rules and store, for zero gain — the IdP's access token already verifies on every call.
- **A per-issuer `flows` admin setting**: rejected by the user — "it is the IdP that decides, not a
  setting of ours; if the password flow is available there it works, if not it does not."
- **Never let the node do ROPC** (keep design/016 §0 absolute): rejected — the password grant is the
  only way a vanilla DBeaver works without our driver, and the org's IdP already gates it.

## Follow-ups

- The custom JDBC driver / acl-login agent (auth-code+PKCE, device) remain separate-repo work; this
  spec makes the node discoverable and password-capable for them.
- ~~quack's discovery document still lists bare issuer URLs~~ — done in the follow-up commit: one
  shared composer (`acl_door_auth.cpp`) now serves both doors, so `GET /.well-known/quack-auth` and
  the Handshake's `discover-auth` answer the same document, and `oidc::FetchQuackAuth` (the
  spec-061 ISSUER-less provider) reads both the old bare-URL shape and this one.
