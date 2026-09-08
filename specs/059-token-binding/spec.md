# Spec 059: token freshness gates the connection, not the connected

- **Status**: implemented
- **Date**: 2026-08-31
- **Author**: hugr-lab

## Summary

Until now a session died the moment its token's `exp` passed (spec 044), judged again on every use.
That rule makes short-lived IdP tokens unusable interactively: a DBeaver session opened at 9:00 with a
5-minute token went dark at 9:05, and nobody in the client stack owns mid-session refresh (the
token-acquisition design, design/016). The decision, settled with the user: **the token's freshness
gates session establishment, not the established session.** A session opened with a valid token keeps
working until it is idle, closed, killed, or capped; `exp` is enforced where the credential is
presented - at open. `acl_session_token_binding = 'connect' | 'every_use'` (default `connect`)
selects the rule; `every_use` restores the old behaviour for shops that want revocation to bite
mid-session.

## Problem

Refresh has no owner in real client stacks: the Arrow JDBC driver, Power BI's connector runtime and a
quack secret all present a token at connect and cannot rotate it mid-session. With exp re-judged per
use, the only workable deployments were long-lived tokens *and* long sessions - the strictness bought
no security (the token was still valid at every judgment) and broke every short-token IdP default.

## Design

- One setting, validated where it is set: `acl_session_token_binding`, VARCHAR, GLOBAL, default
  `connect`; a value that is neither `connect` nor `every_use` is refused by the set-callback. If an
  unknown value ever reaches the judgment anyway, the accessor fails CLOSED to `every_use` - the
  stricter rule, never the weaker one.
- Under `connect` (default), the `exp` clause is skipped in every judgment of an ALREADY OPEN
  session: `SessionSql`, `SessionPrincipal`, `SessionAlive`, `SessionReason` (a live session is
  "live", never "expired"), `SessionCount`, and the sweep. The idle rule (spec 044) is untouched and
  remains the working bound on abandoned sessions; `acl_session_kill` and the cap are untouched.
- **Establishment is always gated**: `SessionOpen` verifies the token in full - `exp` included -
  under either binding. An expired token opens nothing; `connect` only stops re-judging a credential
  that was already accepted.
- The setting is read before the store lock (the SweepLocked discipline) and passed into the sweep.
- **The Flight door's per-call re-verification honours the binding** (the review's chief finding:
  without this, spec 050's F9 - the token is the authority of every call - silently overrode the
  binding, and the flagship scenario failed exactly on the door that serves DBeaver). Under
  `connect`, `SessionFor`'s and `CloseSession`'s re-verification of an EXISTING session's bearer
  runs with `ignore_exp`: the expiry comparison alone is skipped - signature, issuer, audience,
  `nbf`, the exp claim's presence and the roles still verify, and the fingerprint match against the
  bound session still gates. The token remains the cryptographic proof of identity on every call;
  only its staleness is forgiven, and only for a live same-principal session. `SessionOpen` never
  sets `ignore_exp`, so a stale token can continue a session and never start one.
- **Memory mode keeps the strict rule.** Without a policy catalog the store cannot read the setting,
  so it stays at `every_use` - pre-059-compatible and the stricter mode - rather than silently
  ignoring an operator's choice. (Both doors refuse to serve without a catalog anyway.)
- **The reaper-less combination is refused at SET**: under `connect` the idle rule is the only
  automatic reaper, so `acl_session_idle_timeout=0` is refused while the binding is `connect`, and
  entering `connect` is refused while idle is 0 - otherwise every abandoned session would pin
  `acl_max_sessions` forever. And the binding is GLOBAL-only: a session-scoped SET would validate,
  display, and be ignored by the judgment, so it is refused outright.
- Ops note: `acl_sessions()` reports `expires_at` raw; under `connect` a session may legitimately
  outlive it - compare against the clock to see which sessions run on a stale credential, and
  `acl_session_kill` ends any of them.

## Enforcement & security

- The trade, stated: under `connect`, disabling a user at the IdP no longer ends their open session -
  it prevents new ones. The bounds that remain are the idle timeout (default 900s), the explicit ops
  surface (`acl_sessions()` / `acl_session_kill`), and disconnect. A shop that wants exp to bite
  mid-session sets `every_use` and accepts that its clients must bring long tokens or reconnect.
- Fail-closed posture kept: opening still verifies everything; unknown setting values refuse at SET
  and harden to `every_use` at read; nothing widens for an unauthenticated caller.
- The IdP-side lever this unlocks (the user's): issue *longer* access tokens only to the interactive
  analyst clients (Keycloak's Access Token Lifespan is per-client), keep machine clients short -
  under `connect` even short tokens give a full working session, so the pressure for long tokens
  drops rather than rises.

## Testing

`test/e2e/flight/run.sh` proves the flagship scenario end to end through the real door: a cookie
session established with a fresh bearer keeps answering after the server's skew flip makes that
bearer look long-expired (connect), a fresh open under the same skew is refused in both modes, and
flipping to `every_use` refuses the very same call.

`test/sql/acl_session.test`: with a hugely negative `acl_jwt_clock_skew` making every exp look
past-due to the judgment (no sleeps), the default binding keeps an open session answering
(`acl_session_sql` non-NULL, reason `live`, sweep reaps 0); switching to `every_use` refuses the same
session (`NULL`, `expired`, swept); an invalid value is refused at SET; and an expired token cannot
OPEN a session under either binding.

## Alternatives considered

- **Mid-session token rotation** (the client re-presents a fresh token on a live session) - deferred,
  not needed once establishment is the gate; it returns as part of the token-resolver seam if a
  deployment ever wants `every_use` *and* short tokens *and* long sessions.
- **A max-session-lifetime knob** as a third bound - left out until someone needs it; idle + kill +
  disconnect cover the abandoned-session cases today.

## Follow-ups

- design/016 blocks A/B: the acquisition layers (secret provider, discovery, password handshake)
  assume this binding; their specs land next.
