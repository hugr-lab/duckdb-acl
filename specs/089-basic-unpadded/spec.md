# Spec 089: the password handshake accepts unpadded base64

- **Status**: implemented
- **Date**: 2026-09-30
- **Found by**: the Go and Python examples of hugr-lab/acl-clients, logging in with a password

## Summary

The Flight door's password handshake (spec 064) now decodes the `authorization: Basic` value with or
without the trailing `=` padding. arrow-go, which ADBC's Go and Python Flight SQL drivers are built
on, sends it without.

## Problem

The ADBC driver with `username`/`password` against a TLS door failed with
`flight: no authorization header on the response (AuthenticateBasicToken)`. pyarrow's
`authenticate_basic_token` and the JDBC driver worked with the same credentials.

arrow-go's `AuthenticateBasicToken` encodes `user:password` with `base64.RawStdEncoding` (no padding).
duckdb's `Blob::FromBase64` refuses a length that is not a multiple of 4. `BasicFromHeaders` read the
refusal as "not BasicAuth" by design, so the handshake ended OK with no bearer in the response. The
Go client reads headers and trailers joined, so where the header travels was never the issue.

Whether it failed depended on the credentials: `user:password` of a length divisible by 3 has no
padding and worked, so `alice:wonder` (12 bytes) in the e2e never saw it.

## Design

`BasicFromHeaders` restores the padding before decoding: it appends `=` up to a multiple of 4. A
length that is 1 mod 4 is not base64 in either form, and stays "not BasicAuth". No other change: the
header is still read only on the Handshake, the grant, the verification and every refusal are spec
064's.

## Enforcement & security

Nothing is admitted that was not before. The same credentials, decoded, go to the same IdP grant, and
the IdP's token is verified offline as before. Padding is not part of what the client proves.

## Testing

`test/e2e/flight/auth.sh` gains a `password-raw` check (`auth_client.py`) that does what arrow-go
does:

- It sends the Handshake with no message and an unpadded `Basic` value for `bob:builder` (11 bytes, so
  the padded form ends in `=`).
- It reads the bearer from the response through a client middleware and reads the tenant's slice
  under it.

Without the fix it fails with the ADBC driver's own sentence, `no authorization header on the
response`. It was also verified live: acl-clients' Go and Python examples against Keycloak read
globex's 5 of 10 rows as analyst2.

## Alternatives considered

- **Answer the handshake with an empty message, so the header travels as initial metadata.** This
  was tried first, on the guess that a trailers-only response hid the header from Go. It had no effect,
  and reading arrow-go showed it joins headers and trailers. Dropped.
