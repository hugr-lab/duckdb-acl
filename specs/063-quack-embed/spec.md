# Spec 063: the embedded quack door — quack's server compiled into acl

- **Status**: implemented
- **Date**: 2026-09-01
- **Author**: hugr-lab

## Summary

Design/016 block A2, taken to its end: quack's RPC **server** is compiled directly into the acl
extension instead of being reached through the spec-062 loopback front. `acl_quack_serve(uri, token
[, cert, key][, mode])` now raises one listener that owns the public address — it binds it directly,
terminates **TLS** where cert/key are given, answers the unauthenticated **`GET
/.well-known/quack-auth`** discovery document from the live policy, and speaks the quack protocol to a
real client with no proxy hop in between. The spec-062 front is deleted.

## Problem

The spec-062 front put a second HTTP listener on the public address and streamed every request to a
loopback quack. That extra hop cost latency under load (the front's own CI regression tripped quack's
heartbeat lease, patched only by inflating `quack_default_heartbeat_timeout` to 300s), and it capped
concurrency at the proxy rather than at quack's own elastic model. The user asked for the real fix:
take quack as a submodule and run its **original** server inside acl, adapting only the listener.

## Design

### Build — the embedded server graph

- **Submodule** `third_party/quack` (upstream `duckdb/duckdb-quack`, pinned at
  `f28823ddb9b6b9c22e72176f2b8db00cbc8b6e9b`). Only quack's transport-agnostic **server** object graph
  is compiled into acl's `EXTENSION_SOURCES` (protocol machinery: message/serialize, data stream,
  fetch ahead/collector, result cache, rebalancer, uri, log, and `quack_server`). The whole
  client/storage half, the extension entrypoint, `quack_start_stop` and the client admin table
  functions are excluded — the embedded graph links with **zero** undefined symbols.
- **The httplib namespace bridge.** duckdb's bundled httplib renames its namespace to
  `duckdb_httplib_openssl` under `CPPHTTPLIB_OPENSSL_SUPPORT` (its ODR guard against the core's non-TLS
  copy), but quack hardcodes `duckdb_httplib::`. Rather than patch the submodule or shadow its headers
  (sibling quote-includes defeat an `-I` shadow), a force-included shim
  `src/quack_embed/include/acl_quack_httplib_ns.hpp` aliases `namespace duckdb_httplib =
  duckdb_httplib_openssl;` under the macro. The embed graph compiles UNCHANGED under both namespaces;
  TLS is compiled in exactly when the flight build's OpenSSL is present.
- **Enabled by default on every non-WASM target** (WASM has nothing to listen on — there a WASM duckdb
  is a quack *client*, not a server); `ACL_NO_QUACK_EMBED=1` drops it (a stub `acl_quack_serve` then
  reports the door was left out). `ACL_QUACK_EMBED_ENABLED` tells acl's own TUs to call the server.
- **Platform coverage.** The server graph is portable std + duckdb's bundled httplib, with no
  POSIX-only calls, so it builds on the whole distribution matrix (linux amd64/arm, windows MSVC and
  **MinGW**, osx arm — WASM excepted). MinGW is NOT a special case: its only wrinkle is that GCC ignores
  httplib's MSVC `#pragma comment(lib, "ws2_32.lib")`, so `CMakeLists` links `ws2_32`/`crypt32` by hand
  on `WIN32`. **No new dependency** rides in: httplib and mbedtls are bundled in duckdb, OpenSSL is
  already pulled by `arrow[flightsql]` (and the OIDC core), and quack's curl user is the client half,
  which is excluded — so the distribution vcpkg manifest is unchanged.

### The listener — `AclQuackServer`

A sibling of quack's `HttpQuackServer`, deriving the same `QuackServer` base (so `HandleMessage` and
the whole connection lifecycle are quack's own). It owns the httplib listener, and that is the only
difference: it binds the **public** host from the uri, terminates TLS with an inline-PEM
`SSLServer` when cert/key are given (the spec 053 read-through-the-filesystem pattern for the PEM), and
registers `GET /.well-known/quack-auth` whose body is composed from `PolicyStore::ListIssuers()` **per
request** (an issuer added or dropped after the serve shows up immediately). A process-wide registry,
keyed by canonical uri, replaces quack's per-instance one; a server left by an instance destroyed
without `acl_quack_stop` is **reclaimed** by a later serve of the same address (kept from the spec-062
review).

### The SQL surface is separate (`acl_quack_*`)

Strategy B: everything acl registers is `acl_quack_*`-named, so a standalone quack loaded alongside
registers its own `quack_*` names without a clash. The embedded server therefore reads
`acl_quack_*` settings (regenerated rename copies of the few TUs that read settings — `sync.py` from
the submodule) and drains through **`acl_quack_scan_data`** instead of `scan_data_from_quack_client`.
The two auth/authz settings default straight to `acl_quack_authenticate` / `acl_quack_authorize`, so a
plain serve needs no `SET` and quack need not be loaded at all.

### `mode := 'plain'`

`acl_quack_serve(uri, token[, cert, key][, mode])`. Default `'embedded'` is the server above. `'plain'`
drops the discovery route for a bare quack server — still acl-gated, cleartext only (terminate TLS at a
reverse proxy upstream); passing cert/key with `'plain'` is refused.

## Enforcement & security

- **The unprefixed-drain fence catches both names.** A generated ingest `INSERT ... SELECT * FROM
  <scan>('<id>')` arrives unprefixed (spec 042/049); the fence in `acl_parser_override.cpp` now
  recognises **both** `acl_quack_scan_data` (embedded) and the legacy `scan_data_from_quack_client` (a
  co-loaded stock quack), and both are on the function denylist, so a principal cannot call either and
  an unrecovered stream still fails closed.
- **Same preconditions as before.** `acl_quack_serve` still refuses unless a policy source is
  configured, anonymous admin is off, the parser override is STRICT, and a server token is passed.
- **A real CSPRNG for tokens/session ids.** The server mints these from a crypto module. duckdb's
  default one is read-only (it refuses an RNG unless httpfs is loaded), and its bundled mbedtls RNG is a
  non-crypto PRNG (`RandomEngine`) gated behind `force_mbedtls_unsafe` — unfit for auth tokens. Since
  the flight build already links OpenSSL, `acl_quack_serve` registers an OpenSSL-backed
  `EncryptionUtil` (RNG via `RAND_bytes`) into `config.encryption_util` at serve time, **only if none
  is set** (a loaded httpfs still wins) and **only when serving** (a non-serving instance keeps
  duckdb's default posture). So a plain flight build serves with neither `LOAD httpfs` nor
  `force_mbedtls_unsafe`. A non-flight build (no OpenSSL) still needs a crypto module and is refused
  with an acl-framed hint.
- The discovery document is metadata of the same public class OIDC discovery itself serves — where to
  authenticate, never who may.

## Tests

`test/cpp/test_acl_quack_embed.cpp` (replaces the front test): discovery names both issuers; a **real
quack client ATTACHes through the embedded server and reads its RLS slice**; the ISSUER-less provider
secret discovers the issuer from the door; the TLS variant serves https discovery (and cleartext on
the same port does not); `mode := 'plain'` drops discovery yet keeps the acl gate; a leaked server of a
dead instance is reclaimed. Needs an `ACL_QUACK=1` build for the client leg; skips gracefully
otherwise. Full sql suite and all cpp tests green.

## Alternatives considered

- **Keep the spec-062 front.** It works, but the loopback hop and its heartbeat tax are exactly what
  the embed removes; superseded.
- **Patch the submodule header / shadow it.** The namespace-alias shim is smaller (one force-included
  file), keeps the submodule pristine, and self-heals across bumps.
- **Reuse `quack_*` names (minimal fork).** Rejected by the user in favour of clean co-load (Strategy B).

## Follow-ups

- Our PR CI builds linux amd64 + osx arm only; the full matrix (linux arm, windows MSVC/MinGW, WASM) is
  verified by the community-extensions distribution build (`packaging/community-extensions/description.yml`
  — no excluded platforms). Since the embed adds no dependency, that build's footprint is unchanged, but
  the Windows/MinGW *compile* of quack's server is exercised there rather than in our own CI.
- CI inits submodules recursively, which also clones quack's own (unused) nested `duckdb`. The quack
  submodule is marked `shallow`; the nested clone is wasteful but its pins are valid, so it is a CI-time
  cost, not a correctness risk.
- A bump of `third_party/quack` means re-running `src/quack_embed/sync.py` and re-checking the one-line
  namespace assumption; the sync guards fail loudly if a renamed literal has moved.
