# Spec 058: answer the Flight Handshake so the JDBC driver (DBeaver) can connect

- **Status**: implemented
- **Date**: 2026-08-31
- **Author**: hugr-lab

## Summary

The Arrow Flight SQL **JDBC** driver - the one DBeaver embeds and spec 047 named as a target - opens a
connection by calling the Flight `Handshake` RPC. Our door registered no `auth_handler`, so Arrow's
server answered Handshake with *"This service does not have an authentication mechanism enabled"*
(UNIMPLEMENTED), and the driver could not connect at all - though pyarrow and the ADBC driver, which
never handshake and send the token as a per-call header, worked. This registers a
`NoOpAuthHandler` so Handshake is a no-op success. Nothing is weakened: the real gate is unchanged -
every RPC still carries `authorization: Bearer <jwt>`, read per call, and a call without a valid token
is refused exactly as before. Found by live validation (spec 057), which is the first time a JDBC
client touched the door - there is no Java toolchain here to have caught it in CI.

## Problem

`FlightServerOptions.auth_handler` was left unset. Arrow's `FlightServerBase` then rejects the
`Handshake` RPC as unimplemented. The JDBC driver issues that RPC as part of establishing the
connection (before any query), so DBeaver failed at *Test Connection* with the UNIMPLEMENTED message -
a hard block on the JDBC/ODBC ecosystem spec 047 set out to serve, invisible until a real JDBC client
tried it.

## Design

- `options.auth_handler = std::make_shared<flight::NoOpAuthHandler>()` on the served options.
  `NoOpAuthHandler::Authenticate` does nothing and succeeds; `IsValid` returns an empty identity. The
  Handshake RPC now completes instead of erroring.
- **Authentication is untouched.** The door authenticates from the `authorization: Bearer` header on
  every RPC (`TokenFromHeaders` → `SessionFor` → `SessionOpen`), which `NoOpAuthHandler` does not read
  or alter. The handshake carries and establishes nothing; it is a connection formality the JDBC
  driver requires. A client that completes the handshake but sends no valid token is refused at the
  first real call, as it always was.
- The header a JDBC client sends: the Arrow Flight SQL JDBC driver forwards its non-reserved
  connection properties as Flight call headers, so a driver property `authorization` = `Bearer <jwt>`
  reaches the door as the header it already reads. (Documented in the live runbook.)

## Enforcement & security

- No downgrade: `NoOpAuthHandler` makes the *handshake* a no-op, not authentication. The per-call
  Bearer token remains the sole authority; an anonymous handshake grants nothing, opens no session,
  and the first statement of an unauthenticated connection is refused with "authentication failed".
- The handshake establishes no identity (`IsValid` returns empty), so nothing downstream can mistake a
  handshaked-but-tokenless connection for an authenticated one.

## Testing

- The existing header-auth clients are unchanged and still pass: `make test-flight` (run.sh / adbc.sh /
  tls.sh) and the full suite. `NoOpAuthHandler` touches no path they exercise.
- Verified live against a served node: a pyarrow `authenticate_basic_token` (which performs the
  Handshake RPC) now returns a no-op success instead of UNIMPLEMENTED, while a normal header-auth query
  still reads the principal's slice. A JDBC handshake is the same RPC.
- A headless JDBC leg still waits on a Java toolchain (spec 057's follow-up); until then the runbook's
  DBeaver steps are the JDBC proof, and they now get past *Test Connection*.

## Alternatives considered

- **A real handshake auth handler** that accepts the token as a basic-auth password and issues a
  bearer back - rejected: it duplicates the per-call Bearer auth we already have, adds a second
  credential path to keep consistent, and the driver forwards the header directly anyway. The
  handshake only needs to *succeed*, not to authenticate.

## Follow-ups

- The scripted JDBC leg (spec 057 follow-up) would pin this in CI once Java is available.
