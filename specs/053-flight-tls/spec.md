# Spec 053: TLS on the Flight door

- **Status**: implemented
- **Date**: 2026-08-30
- **Author**: hugr-lab

## Summary

The Flight door has bound localhost only since spec 045, refusing any other address because serving in
the clear over a protocol meant to cross machines would hand out data unencrypted. This lifts that
refusal the honest way: `acl_flight_serve(uri, cert, key)` serves Flight SQL over TLS and may bind any
address; `acl_flight_serve(uri)` still serves in the clear and still binds localhost only. TLS is what
makes the door safe to leave the machine, so it is what lets the address leave localhost - one gate,
one lifter. A single node can now serve real clients directly, without requiring a TLS-terminating
proxy in front (though one is still a valid deployment).

## Problem

`RefuseUnlessServable` rejected any non-local host with "this door serves in the clear so far, so it
binds only localhost - TLS is a follow-up". That follow-up is this spec. Everything else a served
node needs - sessions, the catalog RPCs, ingest, the leak audit - has landed; the door's own transport
security was the last thing keeping it on localhost.

## Design

### Syntax

`acl_flight_serve` becomes a two-signature set:

- `acl_flight_serve(uri)` - cleartext, localhost only (unchanged).
- `acl_flight_serve(uri, cert, key)` - TLS, any address. Both arguments required together; a key
  without a cert (or the reverse) is refused before the socket is touched, because that is a
  configuration mistake with a cryptic gRPC failure otherwise.

`cert` and `key` are each **either inline PEM** (recognised by the `-----BEGIN` armor) **or a
path/URI read through duckdb's own filesystem** - the same mechanism spec 023 reads a JWKS document
with (`read_text`). A local file works out of the box; an object-store URI rides httpfs; a secret
manager that can present a path or a text works without a new mechanism. Nothing is written to disk by
us - the material is handed straight to Arrow. What a path yields is validated to be PEM (the
`-----BEGIN` marker) before it reaches Arrow, so a path to the wrong file is a named error rather than
a cryptic gRPC init failure. Both arguments are required together; because a NULL argument would
otherwise short-circuit duckdb's default null propagation and return NULL without ever running the
body (a door that silently does not start), the function declares `SPECIAL_HANDLING` so the
cert-without-key guard always fires.

### Serving

- With certs, the listen `Location` is built as `grpc+tls` whatever scheme the uri was written in -
  the certificate is the intent, and a plain `grpc://` location would open a cleartext listener beside
  the certs. `ParseListenUri` now also returns the port (parsing a bracketed IPv6 literal `[::1]:port`
  correctly - the port is the colon after the closing bracket, not the first colon, which sits inside
  the address), so `Location::ForGrpcTls(host, port)` can be built directly for any address the
  "any address" promise now invites.
- `FlightServerOptions.tls_certificates` gets one `CertKeyPair{pem_cert, pem_key}`. Arrow terminates
  TLS in gRPC; nothing about the ACL, the sessions, the cookie middleware or the rewriter changes -
  the encrypted transport is entirely beneath them.
- `RefuseUnlessServable` takes a `has_tls` flag: the localhost-only rule is the one refusal a
  certificate lifts. The other three (a policy source configured, anonymous admin off, the parser
  override STRICT) stand regardless - TLS secures the wire, it does not make an unsafe instance safe.

### What is deliberately not here

- **mTLS / client certificates.** `FlightServerOptions.verify_client` and `root_certificates` exist,
  but requiring a client certificate is a distribution story (who mints them, how they rotate) that
  the token already covers for authentication - the token is the principal, the cert is the wire.
  Left as a follow-up for a deployment that wants transport-level client identity too.

## Enforcement & security

- Fail-closed: cert-without-key (or the reverse) is refused; a non-local cleartext bind is still
  refused with a message that now points at the TLS form; the three non-TLS servability checks are
  unchanged.
- The token remains the authority of every call over TLS exactly as in the clear - TLS adds
  confidentiality and server authentication, and changes nothing about who a call speaks for.
- Reading cert/key through `read_text` runs as the server (the setup path, not a principal's), the
  same trust level as every other `acl_*` admin input.

## Testing

- `test/e2e/flight/tls.sh`: a self-signed cert; a cleartext bind on a non-local address is refused
  with the localhost reason; a cert-without-key call is refused by the guard; a path to a non-PEM
  file is refused with the PEM reason; an inline-PEM TLS door initializes; a TLS door on a non-local
  address comes up; a pyarrow client that trusts the cert reads its own RLS slice over `grpc+tls`; a
  client that does not trust the cert is rejected specifically by certificate verification. Wired
  into `make test-flight` and the CI flight-door job.
- `test/e2e/flight/client.py` gained `ACL_TLS_ROOT` (a root cert to verify the server), so the same
  third-party client drives the encrypted door.

## Alternatives considered

- **Require a reverse proxy for TLS, keep the door cleartext-localhost forever** - rejected: a single
  node is a supported deployment (design/015), and making every such node run a sidecar proxy for the
  one thing Arrow does natively is friction with no security gain. A proxy stays valid; it is no
  longer mandatory.
- **A separate `acl_flight_serve_tls` function** - rejected: overloading by arity is the duckdb-native
  way (like `acl_use_db`), and one name with an optional cert/key reads as what it is.

## Follow-ups

- mTLS (`verify_client` + a client-CA root) for deployments wanting transport-level client identity.
- Certificate rotation without a restart - the JWKS re-read story (spec 023) again, for the door's own
  cert; not needed until a deployment rotates on a schedule shorter than its restarts.
