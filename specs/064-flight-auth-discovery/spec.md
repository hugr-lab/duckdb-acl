# Spec 064: the Flight door's auth discovery + admin-enabled password handshake (Block B)

- **Status**: draft
- **Date**: 2026-09-01
- **Author**: hugr-lab

## Summary

design/016 Block B, the **node side** of "how a Flight SQL client authenticates without a human
pasting a JWT". The client tooling — a custom JDBC driver, an `acl-login` agent, a Power BI connector
— lives in separate repos (design/016 §3); what the MIT node owes them is two things the Flight door
does not have yet:

- **B2 — discovery.** The door advertises, unauthenticated, the issuers it trusts and the OAuth flows
  the admin allows, so a driver knows *where* to authenticate and *how*. This is the Flight analog of
  the quack door's `GET /.well-known/quack-auth` (spec 062/063).
- **B3 — an admin-enabled password handshake.** For a *vanilla* Flight SQL client (stock Arrow Flight
  JDBC, only Username/Password fields, no custom driver), the door — **only when the admin has enabled
  the `password` flow for that issuer** — exchanges the Handshake's username/password for a token via
  the IdP's resource-owner password grant (ROPC), verifies that token offline exactly like a Bearer,
  and mints a session. Off by default; a deliberate, opt-in relaxation of design/016 §0.

B1 (spec 058's NoOp handshake — the server-side prerequisite that lets a header-Bearer client connect)
is already done.

## Problem

The door verifies an `authorization: Bearer <jwt>` on every call (spec 045), and that is the whole of
its auth. A client that already holds a token works; a client that does not has no way to (a) learn
which IdP to go to, or (b) get a token from stock Username/Password fields. quack got both through its
front's discovery + provider; the Flight door got neither.

### No flow-gate of ours — the IdP is the gate (user, 2026-09-01)

design/016 §2 spoke of an admin "flow menu"; the user's refinement removes our half of it: **the IdP
decides whether the password grant is allowed, not a setting of ours.** The node does not carry a
per-issuer `flows` toggle. It simply attempts the grant against the issuer; an IdP that permits ROPC
answers with a token, one that does not answers `unsupported_grant_type`/`invalid_grant`, and that IS
the refusal. One fewer setting, and the policy lives where it belongs (the org's IdP config). The only
issuer config the grant needs is the **client_id** it authenticates the grant as — the same app
registration whose tokens the node already verifies (added to `acl_define_issuer`, optional
client_secret for a confidential client). That is the credential for the call, not a gate.

### B2 — discovery (unauthenticated)

A Flight `DoAction("discover-auth")` (unauthenticated — the NoOp handshake path, no Bearer required)
answers a JSON body: the issuers from `PolicyStore::ListIssuers()` and, per issuer, the OIDC endpoints
discovered from `.well-known/openid-configuration` (whose presence tells a driver what the IdP itself
supports — a `device_authorization_endpoint` means device flow is there, etc.). Same class of public
metadata OIDC discovery serves — where to authenticate, never who may. Shape mirrors `oidc::DoorAuth`
so the same client code reads a quack door and a Flight door.

### B3 — password handshake (the IdP gates it)

Replace the door's `NoOpAuthHandler` with a handler that:
- still makes a Bearer-header call a no-op success (B1 unchanged — the header is the real gate);
- when the Handshake carries **BasicAuth** (username/password): run `oidc::Discover(issuer)` +
  `oidc::PasswordGrant(ep, client_id, …, username, password)` (spec 060, already built) against the
  configured issuer, **verify the returned access token offline** (the same `VerifyPrincipal` every
  Bearer takes), mint a session, and return the session token as the Handshake's bearer, which the
  driver then sends as `authorization: Bearer` on every subsequent call;
- surfaces the IdP's own refusal when the grant is not permitted there (no token minted).

With more than one issuer configured the door tries the issuer whose config carries a client_id (an
issuer with no client_id cannot do ROPC and is skipped); a single-issuer node is the common case.
The password is used once to obtain a token and **never logged, never stored, never re-sent**.

## Enforcement & security

- **§0 relaxation is gated by the IdP, not by us.** The node runs ROPC only from a BasicAuth
  handshake, and only succeeds when the org's IdP permits the password grant — the policy lives at the
  IdP, exactly where an org already decides whether ROPC is acceptable. Every other path keeps the
  invariant. The resulting token is still verified offline — the node trusts the IdP's answer, not the
  password.
- **Discovery leaks nothing private** — issuer URLs and flow names, the same facts a `.well-known`
  document publishes. Unauthenticated by design.
- Password is transient (grant → discard); TLS (spec 053) is the transport for the handshake carrying
  it, and a non-TLS door should refuse `password` (a cleartext password on the wire is the one thing
  worse than the node seeing it).

## Tests

- discovery: `DoAction("discover-auth")` with no Bearer answers the configured issuers + flows.
- password handshake: with `password` enabled for the fixture issuer, a BasicAuth handshake against a
  fake IdP mints a session and a follow-up query reads the principal's slice; with it disabled, the
  handshake is refused by name; a Bearer-only call is unaffected either way.

## Alternatives considered

- **GetSqlInfo for discovery** instead of DoAction: GetSqlInfo is reached after connect and is
  awkward to answer unauthenticated; DoAction is the cleaner unauthenticated pre-auth call.
- **Never let the node do ROPC** (keep §0 absolute): rejected by the user — the password grant is the
  only way a vanilla DBeaver works without our driver, and the org's IdP already gates whether ROPC is
  allowed, so the node deferring to it is not our policy call to make.
- **A per-issuer `flows` admin setting** to enable/advertise password: rejected by the user — "it is
  the IdP that decides, not a setting of ours; if the password flow is available there it works, if
  not it does not — no second setting."

## Follow-ups

- The custom JDBC driver / acl-login agent (auth-code+PKCE, device) remain separate-repo work; this
  spec only makes the node discoverable and password-capable for them.
