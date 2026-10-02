# Spec 097: the `observe` capability - who may read the node's load report and metrics

- **Status**: implemented (owner, 2026-10-02: the open mode stays as an explicit opt-out, default off; `/metrics` under `observe` too)
- **Date**: 2026-10-02
- **Follows**: spec 079 (the load report), spec 069 (`/metrics`), spec 096 (the report names the node's
  group and profile version), spec 009 (administration as a capability), design/076 §5.2 (the owner's
  "open for P1, `observe` with resource groups"), design/017 §3.2 / §6 (the last acl item of the
  platform's phase 1)

## Summary

A new global administration scope, **`observe`**: reading the node's load report and its Prometheus
metrics. With it, `GET /.well-known/acl-node`, `GET /metrics` and the Flight Handshake payload
`node-load` answer only a bearer token whose roles hold `observe` (or `passthrough` / unrestricted
`manage`, which already read everything). The orchestrator's front and node agent read the report
with a service role that holds `observe` and nothing else - no `manage`, no data.

The metrics themselves are increasingly pushed, not pulled: a node runs `acl_otel`, which exports
the same counters and gauges over OTLP. The pull endpoints stay for a front that routes by load and
for a standalone node scraped by Prometheus.

## Problem

- While `acl_metrics_endpoint` is on, the three surfaces answer **anyone who reaches the port**.
  Design 076 accepted that for P1 because the report carried only counts. Since spec 096 it carries
  operator vocabulary - the node's resource group, every group's live sessions against its
  `max_sessions` (`sessions.by_group`), the profile versions (`config.target` / `applied`) - and the
  door's port is the one clients reach.
- The only alternative today is `passthrough`: the front would have to hold the strongest scope there
  is (native SQL outside the virtual catalog) to read a JSON document. A front holds no policy and
  must not be able to do more than route (design/015 §3, 017 §3.3).

## Design

### 1. The scope

- `acl_grant_admin(role, 'observe')` / `ACL ADMIN GRANT ADMIN observe TO ROLE r` (the existing
  grammar and table: `admins.scope = 'observe'`, `vcat` empty - the report is the node's, never a
  catalog's). Revoke as today.
- **Ordering**: `NONE < OBSERVE < MANAGE < PASSTHROUGH`. `observe` grants **no** administration:
  every check that today reads "has a scope" (`rights.scope == NONE` refuses `ACL <mgmt>` /
  `ACL NATIVE`) becomes "has at least `MANAGE`". Each of the 13 sites that compare `AdminScope` is
  reviewed (§ Enforcement).
- **Implied by** `passthrough` and by **unrestricted** `manage` - both can already read the report
  (`ACL NATIVE SELECT acl_node_load()`, or the management surface). A catalog-scoped `manage` does
  not imply it: the report is node-wide.
- **A privileged role** (spec 095): a role holding `observe` is reached only through a client's own
  mapping, like `manage` / `passthrough` - `acl_identity_store.cpp`'s "any scope" test already
  counts it, which is the right answer (an IdP group named like the role must not grant it).
- Memory mode: `admin_scopes` takes `OBSERVE` the same way.

### 2. The three surfaces

| Surface | How the token arrives | Answers |
| --- | --- | --- |
| `GET /.well-known/acl-node` (quack listener) | `Authorization: Bearer <jwt>` | 200 + the report |
| `GET /metrics` (quack listener) | `Authorization: Bearer <jwt>` (Prometheus `authorization.credentials_file`) | 200 + text |
| Flight Handshake payload `node-load` | the Handshake call's `authorization` header - `Bearer <jwt>` or the bare token, as the door's other calls read it | the report |

- **Refusals**: no token or one that does not verify - 401 with `WWW-Authenticate: Bearer` (Flight
  `Unauthenticated`); a verified principal without `observe` - 403 (Flight `Unauthorized`, gRPC
  PERMISSION_DENIED); the switch off - 404 as today (Flight `NotImplemented`); a decision the node
  cannot make - its policy source or keys failing (`source_error`) or an identity policy it cannot
  apply (`policy_error`: a refused key location, an ambiguous client), or a failure with no note at all
  (a catalog read that failed between freshness checks) - 503 (Flight `Unavailable`): the node's fault
  is never reported as the caller's bad token. A refusal of the token itself always reads `acl_rewrite:
  token rejected: …`, and only that is a 401.
- **Known**: a token naming an issuer the node cannot currently resolve (its secret unreadable) is a
  503, before its signature is checked - as for `SessionOpen`. A caller can raise
  `acl.door.observe{result="source_error"}` that way; it cannot make a front mark the node down (a
  front sees only its own answers). The body says no more than the status (no
  reason a scanner could use); the audit has the reason.
- The token is verified exactly as a session's (`VerifyJwtPrincipal`: issuer, client, audience,
  `exp`, roles - spec 095), offline against the cached keys. No session is opened.
- **Not covered** - and staying unauthenticated by design: the discovery documents
  (`/.well-known/quack-auth`, Flight `discover-auth`) a client reads *before* it has a token, and the
  503 `draining` of quack's discovery (a load balancer's health check has no token).

### 3. The open mode (owner, 2026-10-02: kept, default off)

`acl_metrics_endpoint` stays the switch that the routes exist at all. A second GLOBAL setting,
**`acl_observe_unauthenticated`** (default `false`), restores today's behaviour for a standalone node
scraped by a Prometheus without credentials. It is a deliberate opt-out, refused under a principal
like every `acl_*` setting, and the load report says which mode is in force.

### 4. Cost on the hot path

The front polls every node every 1-2 s per replica (017 §3.3). No new cache is needed: the admin rows
are already cached per principal until the next policy version (the catalog backend's rights cache),
the keys per location (spec 071) - what a poll costs is one signature check plus the cached role
reads `VerifyPrincipal` does anyway. A revoke is therefore
seen at the next policy version, like every other cached decision.

### 5. Audit

- Every read is a `door` event `observe_<surface>` (`node_load` | `metrics`): a refusal is recorded
  (reason `principal`, `capability`, `source_error` or `policy_error`), rate-limited like every
  refusal (`acl_audit_denials_per_second`). A refusal without a principal (no or a bad token, a 503)
  falls in a bucket of its own, `door:<door>:observe` - a tokenless `GET /metrics` is the cheapest
  refusal there is and must not keep the door's refused logins out of the record; a 403 carries its
  principal and is bucketed by it, like every principal's refusal. An allowed read is at level `all` only, so at the default level it
  is counted, not recorded - a 1-2 s poll as a recorded event would drown the trail.
- The counter `acl.door.observe{door, surface, result}` (`result` = `allowed` or the reason code -
  bounded sets).

## Enforcement & security

- **Fail closed**: no token, a bad token, a token without the scope - nothing is answered. A policy
  source that fails answers 503 (the decision cannot be made), never the report.
- **`observe` never administers**: the ordering change is the risk - a site that tested `!= NONE`
  for "may administer" would let an observer in. Every `AdminScope` comparison is listed in the PR
  and covered by a test that an observe-only principal is refused `ACL <mgmt>`, `ACL NATIVE`,
  `ACL ADMIN`-anonymous-equivalents and the identity writes.
- **Forward compatibility of the scope column**: today an unknown scope in `admins` *throws* in
  `ParseAdminScope` (every rights check of a principal holding that role fails with an error). This
  spec changes the read path to treat an unknown scope as **no scope** (fail closed, skipped
  silently - `TryParseAdminScope`), so a later scope never breaks an older build inside the schema
  window (spec 094). It still marks the role **privileged** (`AdminRights::unknown_scope`): a role
  that administers something this build cannot read must not become reachable by an IdP group's name
  (spec 095) - the review's catch, with a regression test. Writing one is still refused by name
  (`GRANT ADMIN superpowers`). An `observe` row scoped to a catalog (only a function driver can write
  one) grants nothing: the report is the node's.
- **The opt-out is the node's**: `acl_observe_unauthenticated` is one of the hardening settings the
  cluster profile refuses (spec 093) - a profile write cannot open every node's report at once. v18 builds still throw on `observe` - they are unreleased, so no `min_reader` bump.
- The report itself stays as spec 079/096 define it: counts, states, group names - never a principal,
  a handle or an object name.

## Testing

- `test/sql/acl_observe.test`: grant/revoke `observe` (functions in memory mode, SQL in catalog
  mode); an `observe` row scoped to a catalog stays privileged; an observe-only principal is refused `ACL <mgmt>` and `ACL NATIVE`; observe beside a
  catalog-scoped manage manages only that catalog; an unknown scope in `admins` reads as none but keeps
  the role privileged; for both an observe role and an unknown-scope role an issuer-wide mapping is
  refused and an unmapped token naming the role has no recognized roles (spec 095); the report's
  `"observe"` mode; the opt-out refused under a principal.
- `test/cpp/test_acl_quack_embed.cpp`: per route 404 off, 401 no/bad token (with `WWW-Authenticate`),
  403 without the scope and for a catalog-scoped manage, 200 for observe, an unrestricted manage and
  passthrough; `acl_observe_unauthenticated` restoring 200 without a token; the counters (after the
  audit worker drains). The 503 path is not exercised by a test (a failing source in the embed test
  would need a breakable policy catalog) - it is covered by reading: every failing call maps to it.
- `test/e2e/flight/auth.sh`: `node-load` without a bearer (`FlightUnauthenticatedError`), with one
  lacking the scope (`FlightUnauthorizedError`), with an observer reached through the client's own
  mapping (the report); the mappings are dropped again so the later sections keep their principals.
- `test/e2e/door/bootstrap.sql` scrapes `/metrics` through `acl_observe_unauthenticated` - the
  harness is about the door under load, and the opt-out is what a credential-less scraper uses.

## Alternatives considered

- **Keep it open** (076 P1): rejected - since 096 the report names the operator's groups and sizes.
- **Require `passthrough`**: rejected - the front would hold native SQL to read a JSON document.
- **A separate shared secret for the endpoints** (a static bearer configured on the node): rejected -
  a credential outside the identity model, in the node's configuration, which the owner's rule ("no
  credentials written anywhere") forbids; the IdP already issues the front's token.
- **mTLS for the scrapers**: a deployment option on top, not a replacement - the role is what is
  granted, and rotating client certificates is the problem tokens already solve.

## Decisions (owner, 2026-10-02)

1. **The open mode stays** as `acl_observe_unauthenticated` (default `false`) for a standalone node
   scraped by a Prometheus without credentials; nodes with `acl_otel` push their metrics anyway.
2. **`/metrics` is under `observe` too** - the same audience as the load report, one rule.

## Follow-ups

- The node agent's own writes (`acl_cluster_applied`) stay `passthrough` (spec 096); `observe` is
  read-only by definition.
