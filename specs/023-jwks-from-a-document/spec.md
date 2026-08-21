# Spec 023: an issuer's keys read from a document

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

An issuer could only carry keys an operator had pasted into it. It may now name a **document** to read
them from instead — an https JWKS URL or a file kept up to date out of band — read through DuckDB's own
filesystem, cached per instance with a refresh interval and a bounded staleness. Rotation stops being
a manual step.

## Problem

Spec 007 verifies JWTs offline against keys in the issuer row, rotated "by the gateway or admin". Real
issuers rotate on their own schedule and publish a JWKS; pasting keys means someone must notice a
rotation and act before tokens start failing. That was acceptable while a gateway sat in front. It
stops being acceptable the moment the node authenticates for itself (roadmap, step 2): a node that
verifies tokens needs key rotation before it needs a socket.

## Design

**`jwks_uri` on the issuer, read through DuckDB's filesystem.** The read is
`SELECT content FROM read_text(<uri>)` on an internal connection. Consequences, all of them the point:

- **No HTTP client of ours.** The extension has no vcpkg or OpenSSL dependency and this does not add
  one. Proxies, certificates, retries and timeouts are the engine's business, where an operator
  already configures them.
- **An https URL and a local file are the same mechanism.** `read_text` opens either. A deployment that
  cannot reach the issuer from the database can have something else drop the JWKS in a file; a
  deployment that can, points at the issuer directly. Both are one code path — and the file form is
  what makes this testable offline.
- **httpfs says so itself.** An https URI without httpfs fails with DuckDB's own message naming the
  extension to install, which is the error an operator needs.

**Keys and location are alternatives.** An issuer states exactly one; `acl_define_issuer` refuses both
or neither, and `ALTER ISSUER … SET KEYS` / `SET KEYS FROM` clears the other — an issuer pointed at a
document must not keep verifying against a paste nobody can see any more.

**The cache is the mechanism.** Per instance, in memory:

| when | what happens |
| --- | --- |
| nothing cached, or the cache is older than `acl_jwks_refresh_interval` (300s) | read |
| the token names a `kid` the cached document does not have | read, no more often than every 10 seconds — a rotation is worth a read, once per token is not |
| the read fails and something is cached | keep using it until `acl_jwks_max_stale` (3600s) has passed since the last **successful** read; `0` means a failed read is fatal at once |
| the read fails and nothing is cached | refuse, naming the location and the reason |

Keys of unknown age stop being trusted deliberately: an issuer that has been unreachable for a day
says nothing about a key that may have been revoked in the meantime.

### Key selection, corrected

Checking this against a live Keycloak showed two things worth fixing, both about what an operator sees
during a rotation:

- **A real JWKS carries more than one key.** A Keycloak realm publishes an RSA-OAEP encryption key
  beside its RS256 signing key. `use` states what a key is for (RFC 7517), and an encryption key must
  never verify a signature; it is now skipped.
- **A `kid` that matches nothing is an error.** It used to fall back to another key of the same type,
  so a token from mid-rotation failed with *"signature verification failed"* — which sends the reader
  after the wrong problem. It now says there is no usable key.

## Enforcement & security

- **The document is only ever read as keys.** Its contents never reach a caller: a JWKS that does not
  parse, or does not hold the right key, produces the same verification failures as before.
- **Defining an issuer now makes the server read a location its administrator chose.** That widens
  what the `manage` capability can cause — from writing policy rows to opening a file or a URL as the
  server. No content is disclosed and no request body is controlled, but reachability *is* observable
  through the error, which is a mild probe. It is called out here rather than left implicit; an
  allowlist of permitted prefixes, or requiring `passthrough` for this one field, is the way to close
  it if a deployment cares (see design/009 on where infrastructure administration belongs).
- **A URI is not a secret and is listed**; keys still are not — `acl_issuers()` has no key column, and
  the test asserts that.
- The memory-backed store cannot read documents (it has no database handle) and says so.

## Testing

`test/sql/acl_jwks.test` (40 assertions): a token verified against keys read from a file; rotating the
file rotating the keys, with `acl_jwks_refresh_interval = 0` making that visible without waiting;
a location that cannot be read refused with `acl_jwks_max_stale = 0`, naming the location; keys and
location refused together and refused absent; `ALTER ISSUER … SET KEYS FROM` and `SET KEYS` each
clearing the other; the operator's listing showing the location and still not the keys; a pasted JWKS
unaffected; and a Keycloak-shaped JWKS — an encryption key beside a signing one — where the signing
key is still found by `kid`, the encryption key is not usable, and an unknown `kid` says so.

## Alternatives considered

- **Vendor an HTTP client** (mbedtls can do TLS). It would mean writing certificate handling, proxy
  support and retry logic that DuckDB already has, for a feature that reads one small document.
- **Fetch on a timer, in the background.** Predictable load, but it needs a thread and it refreshes
  issuers nobody is using; reading on demand behind a TTL costs one read per interval per live issuer.
- **Cache in the policy catalog** so instances share a fetch. Rejected with the single-instance scope:
  a shared cache is the cluster repo's problem, and writing to the policy source on a read path is a
  worse shape than one read per node per interval.
- **OIDC discovery** (`.well-known/openid-configuration` → `jwks_uri`). Worth having, but it is a
  second read and a second failure mode; a `jwks_uri` is one line for an operator to copy today.

## Follow-ups

- **Discovery**: accept an issuer URL and resolve `jwks_uri` from its OIDC document, refreshing both.
- **An allowlist for locations**, or moving the field behind `passthrough` — see the security note.
- **A listing of what the cache holds** (last read, last error, key ids) so an operator can see why
  tokens are failing without reading logs.
