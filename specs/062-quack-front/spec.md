# Spec 062: the quack front - TLS and discovery, with quack unchanged

- **Status**: superseded by 063
- **Date**: 2026-08-31
- **Author**: hugr-lab

> **Superseded by [spec 063](../063-quack-embed/spec.md)**: the loopback front is replaced by quack's
> server compiled into acl (`AclQuackServer`). The public bind, TLS termination and the
> `/.well-known/quack-auth` discovery route move onto that one listener — no proxy hop, no heartbeat
> headroom tax. The `acl_quack_serve(uri, token[, cert, key])` surface is unchanged (063 adds a `mode`
> argument); the front code (`src/quack_front/`) is deleted.

## Summary

Design/016 block A2, the user's own architecture ("quack_acl_serve"): the quack door's PUBLIC bind
now belongs to a front listener our extension owns. `acl_quack_serve(uri, token[, cert, key])`
moves the real quack to a loopback-only port nothing can reach around, and the front: terminates
**TLS** where cert/key are given (inline PEM or a location read through duckdb's filesystem - the
spec 053 pattern), answers the unauthenticated **`GET /.well-known/quack-auth`** discovery document
itself (the issuers the node trusts, composed from the policy PER REQUEST), and streams every other
request to the loopback quack. **quack is unchanged** - and its client already speaks https to
non-local hosts by default (`enable_ssl = !IsLocal()`), so a TLS front is exactly what a remote
client expects. On the client side, the provider (spec 061) may now omit `ISSUER`: a secret whose
`SCOPE` names a concrete door discovers the issuer from the door's own document.

## Design

- `src/quack_front/acl_quack_front.cpp` - one more bundled-httplib TU (the single-TU discipline of
  specs 060/061; `ACL_OIDC_TLS` brings `SSLServer`, in-memory PEM via `PEM_read_bio_*`, no key on
  disk). Deliberately store- and duckdb-free: the discovery document arrives as a callback.
- **The document is live**: composed per request from `PolicyStore::ListIssuers()` (catalog,
  memory, and empty-in-function-driver modes), through a callback capturing SHARED ownership of the
  store - an issuer added or dropped after the serve is advertised immediately. The front's own
  test caught the frozen-string version lying; the callback is the fix.
- Serve: parse the public host:port (quack's own uri grammar, IPv6 included), pick a free loopback
  port for the real quack, start quack there, start the front; a front that cannot start stops the
  loopback quack again and leaves nothing behind. Stop: the front is stopped first and names the
  loopback quack behind it; a uri with no front falls through to a plain `quack_stop` (compat).
- The proxy forwards method, path, body and content type with a generous read timeout (a SEND_DATA
  drain is legitimate long work); a per-request upstream client avoids stale keep-alives.
- Provider-side discovery: `FetchQuackAuth(base)` in the OIDC core; the secret derives the door
  base from its `quack:host:port` SCOPE (loopback speaks http, anything else https - mirroring
  quack's client rule), refuses ambiguity by count, and keys its refresh chain by the RESOLVED
  issuer so a discovered issuer and a spelled-out one share a chain.

## Enforcement & security

- The discovery document is metadata of the class OIDC discovery itself publishes: WHERE to
  authenticate, never who may; it grants nothing and needs no session.
- The loopback quack binds 127.0.0.1 only - there is no path around the front's TLS.
- TLS on a build without OpenSSL is a named refusal, never a silent cleartext fallback; a cert
  without a key (or vice versa) is refused; non-PEM material is refused where it is read.
- The fenced-drain rule (spec 042/043) is untouched: the same store judges the same statements;
  the front adds transport, not policy.

## Testing

`test/cpp/test_acl_quack_front.cpp` (make test-cpp, skips without an ACL_QUACK build): the
well-known names every configured issuer; a real quack ATTACH rides through the proxy and reads its
RLS slice; two advertised issuers make an ISSUER-less secret refuse with a count; after dropping
one, discovery fills ISSUER by itself and the secret mints (pinning the LIVE document - this is the
scenario that caught the frozen version); the TLS front serves the same discovery over https
(curl -k against a throwaway openssl cert) while cleartext on the same port does not. The quack
integration suite and the door e2e now run THROUGH the front, so every existing drain/staging pin
doubles as a proxy regression.

## The review's findings (applied / recorded)

The adversarial review confirmed the core (remote clients cannot reach quack around the TLS front;
the loopback quack still enforces the full ACL) and found no exploitable memory-safety bug - the
cert/key double-free, the post-teardown UAF, SSRF and payload truncation all dissolved on tracing
(httplib up-refs the PEM objects and only frees the SSL_CTX; the CatalogBackend's
`weak_ptr<DatabaseInstance>` plus httplib's `catch(std::exception)` turn a discovery hit after
instance death into a benign HTTP 500; the proxy target is the fixed literal `127.0.0.1`; httplib's
default payload max is `SIZE_MAX`). Two structural findings and the edges are addressed:

- **A leaked front of a dead instance is reclaimed** (was: refused forever, thread + public port +
  store leaked). The front now carries a `weak_ptr<DatabaseInstance>`; a serve of an address whose
  existing front's instance has expired reclaims it (stops and joins the zombie listener) and takes
  its place. Pinned by a test that serves from a to-be-destroyed instance, drops it, and re-serves
  the same address.
- **IPv6 parsing is validated** on both sides: `ParseQuackEndpoint`'s bracket branch now falls
  through the host/port guard (empty host, non-numeric or out-of-range port refuse), and the
  provider classifies an IPv6-loopback door (`quack:[::1]:port`) correctly instead of forcing https.
- **Test robustness**: the https leg skips (not fails) when `curl` is absent, matching the quack/
  openssl skips.

Recorded, not code-fixed (a decision, honestly the better posture than pre-062):

- **The front does not verify the loopback listener is still its quack.** If the internal quack is
  stopped out of band (a raw `quack_stop` on the internal uri, never through `acl_quack_stop`) while
  the front lives, and a *local* process on the host then binds the freed loopback port, the front
  would forward client bodies (bearer tokens) to that squatter. This requires local host access AND
  an out-of-band stop; the supported teardown is `acl_quack_stop` on the public uri, which stops the
  front first. Net token exposure is *better* than pre-062 (where quack listened on the public bind
  in the clear, so a network attacker read tokens off the wire); the residual is a local-only
  window. A future bind-and-hold handoff (quack binds and reports its port, or the front passes the
  socket) would close it - noted for the quack side.
- **Discovery is unauthenticated and lists issuer URLs**, which may name internal IdP hosts - the
  same public class of fact OIDC discovery itself serves; an operator who considers issuer hostnames
  sensitive fronts the door on a network they trust for that metadata.

## Alternatives considered

- **TLS inside quack** - quack's server is deliberately plain ("the server will always listen
  without SSL"); teaching it TLS is a larger quack change for no gain over fronting, and the front
  is where discovery lives anyway.
- **A frozen discovery string** - shipped first, caught by the test, replaced with the callback.

## Follow-ups

- The front listener could serve the FLIGHT door's discovery twin (`DoAction("discover-auth")`,
  design/016 B2) content on an http endpoint too, once B2 lands.
- Advertised client_id/flows in the document need a policy-side home (a catalog column) - design
  material for the flow-menu-as-config work.
