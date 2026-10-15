# Spec 130: the node's own IdP requests trust `ca_cert_file`

- **Status**: implemented
- **Date**: 2026-10-15
- **Author**: Claude (with the owner)

## Summary

The node reads most of the network through duckdb (httpfs), which honours `ca_cert_file`. A few requests go through
the OIDC core's own client instead: the Flight door's discovery and password grant, and the quack provider secret's
flows. That client verified against the system's roots only, so an IdP behind a private CA could not be reached from
those paths even with `ca_cert_file` set. duckdb-ext-common v0.13.0 (its spec 016) gives the client a CA bundle that
is trusted **beside** the system's roots. acl moves to that tag and hands the client DuckDB's `ca_cert_file` on each
of those paths. tresor did the same for its own client (tresor spec 030).

## Problem

Behind a private CA (a sovereign cloud, an on-prem Keycloak), the operator sets `SET GLOBAL ca_cert_file`. Today:

- the door's key documents (the issuer's discovery and its JWKS, spec 023/095) are read through httpfs and work;
- the Flight door's `discover-auth` names the issuer but without its endpoints, because the OIDC discovery in
  `DiscoverEndpointsCached` fails certificate verification;
- the Flight password handshake is refused with *"OIDC discovery against X failed: ..."*;
- the same quack door's `/.well-known/quack-auth` lacks the endpoints;
- `CREATE SECRET (TYPE quack, PROVIDER oidc, ...)` fails at discovery for every flow but `token`.

## Design

- **Pin**: `duckdb-ext-common` moves v0.12.0 → v0.13.0. The contracts are unchanged (ACLA 3, ACLC 2); only the OIDC
  core changed (`SetDefaultCaBundle` / `CaBundleScope`).
- **Which value**: httpfs's `ca_cert_file` setting. Empty, NULL, or absent (no httpfs) means the system roots alone,
  as before.
  - The door's requests read the **instance's global** value (`PolicyStore::CaBundle()`): a door has no client
    context of its own, and a principal cannot set it (spec 068's allowlist holds only `TimeZone` and `Calendar`).
  - The provider secret runs in the creating client's context and reads that context's current value, the way
    httpfs's own file opener does.
- **Where**: one `oidc::CaBundleScope` (thread-local, ends with the call) around each such request.
  - `DiscoverEndpointsCached`: the door's discovery, behind the Flight `discover-auth`, the quack door's
    `/.well-known/quack-auth` and the Flight password handshake.
  - `oidc::PasswordGrant` in the Flight handshake.
  - `Acquire` in the provider secret: door discovery, issuer discovery, refresh, client credentials, password,
    device begin and poll, all on the calling thread.
- **The discovery cache** (process-wide, 300 s, a failure 30 s) is keyed by the issuer **and** the bundle. A change
  of `ca_cert_file` is therefore read at the next request. An endpoint learned under one trust is never served under
  another.

## Enforcement & security

- Verification stays on. The bundle only adds trust anchors, and only the operator's: `ca_cert_file` is a GLOBAL
  setting that a principal cannot set. In hugr-node it is also a hardening setting, outside any profile.
- A bundle that cannot be read, or that holds no certificate, fails the request (ext-common's rule). It never falls
  back to the system's roots alone.
- Nothing else changes: `acl_jwks_locations` still judges every URL before it is fetched, the token endpoint
  included, and the token the IdP answers is still verified offline.
- Two semantics coexist, and the docs say so. The OIDC core's client trusts the bundle **beside** the system's roots,
  while httpfs (the key documents) trusts it **instead of** them. A bundle for a node that also reaches public IdPs
  carries the public roots too.

## Testing

`test/e2e/flight/ca_bundle.sh` (in `make test-flight`). A test CA signs a localhost certificate, and the fake IdP of
spec 064 serves https with it. The door's issuer is that https URL.

1. With `ca_cert_file` = the CA:
   - `discover-auth` carries the token endpoint;
   - the password handshake earns the tenant's slice.

   Both fail without this spec: the client ignored the bundle.
2. With `ca_cert_file` set back to `''`, the handshake is refused at discovery. This proves verification is on and
   that the cache does not serve the endpoint learned under the CA.
3. On a client process with the quack loadable:
   - `CREATE SECRET (TYPE quack, PROVIDER oidc, FLOW 'password', ...)` against the https IdP succeeds with
     `ca_cert_file`;
   - without it, the same secret fails at discovery.

The script SKIPs without a Flight build, pyarrow, openssl or the quack loadable. The CI flight job has all four, and
there a SKIP fails the step.

## Alternatives considered

- **Route the OIDC core through duckdb's HTTP client** (a `Transport`, tresor's `tresor_http_client = 'duckdb'`).
  This gives one semantics with httpfs, but it is more code, and it makes the door's password grant depend on which
  httpfs client is loaded. The CA bundle is ext-common's own answer to the same gap.
- **A setting of our own** (`acl_ca_bundle`). The operator would then have two settings for one trust. tresor reads
  `ca_cert_file` too, so one setting serves the whole node.

## Follow-ups

- None in acl. hugr-node re-pins acl and tresor together (its build compares the two copies of ext-common's
  headers).
