# Spec 068: Client-local settings — a session may set how its own results render

- **Status**: implemented
- **Date**: 2026-09-03
- **Author**: hugr-lab

## Summary

`SET` was refused outright under a principal, so a client could not set its time zone — and a
`TIMESTAMPTZ` rendered in the server's zone is a *wrong answer*, not a cosmetic one. This admits
exactly the two render-only settings (`TimeZone`, `Calendar`), with a constant value and a session
scope, and only through a **session of the client's own** (`ACL SESSION` — a door's client, whose
session IS a connection, spec 050). A per-statement prefix a gateway writes runs on a connection the
gateway shares between principals, so a setting left there would be the next principal's wrong
answer: it stays refused. The Flight door's `SetSessionOptions`/`GetSessionOptions` land on the same
allowlist and the same session connection, so the SQL path and the protocol path cannot disagree.

## Problem

The statement gate's `default: Deny` swallowed every `SET` (spec 052 confirmed `current_setting` and
`getvariable` denied — safe, but the *setting* side had no door). A DBeaver user in Tokyo reads
`2026-01-01 09:00:00+09` as `2026-01-01 00:00:00+00`; a driver that calls `SetSessionOptions` for the
time zone got `NotImplemented`. Design/010 §3.8 named the fix: a small allowlist of session-local,
render-only settings, enforced in the gate as well as in whatever session-options RPC a server exposes.

## Design

- **One allowlist**, `ClientSettingAllowed(name)` in `acl_policy.hpp`: `TimeZone`, `Calendar`
  (both ICU's). Nothing that changes what a name resolves to (`search_path`), what is read
  (`file_search_path`, `enable_external_access`), or what a statement costs (`threads`,
  `memory_limit`). Growing the list is a spec, not a line.
- **The principal knows whether it owns its connection**: `Principal::session_connection`, set only
  by the `ACL SESSION` prefix (never by `ACL INGEST`, which carries the door's composed INSERT).
- **The gate** (`RewriteSetStatement`): refuse a name outside the list (and `SET VARIABLE`); refuse
  `GLOBAL` (a global setting changes the node for every principal); refuse without
  `session_connection` (the gateway's shared connection); require a constant value (no expression
  reads anything on its way into a setting); `RESET` of a listed name is allowed on a session.
  `AUTOMATIC` and `SESSION` scopes are the same thing here — the session.
- **The Flight door**: `SetSessionOptions` needs a connection-long (cookie) session like every
  session resource; each option must be a listed name with a string value (a `monostate` erases —
  `RESET`), applied as SQL `SET`/`RESET` on the session's connection under its `exec` lock; the
  per-option error map answers `kInvalidName` / `kInvalidValue`. `GetSessionOptions` reads the listed
  settings back through `current_setting` on the session's connection — the door's read, never the
  principal's (the function gate still denies a principal `current_setting`).
- **quack**: a client's `SET TimeZone` arrives through `acl_quack_authorize` as
  `ACL SESSION '<h>' SET …` and runs on the quack connection's own duckdb connection — the gate is
  the whole mechanism, nothing door-specific.
- **The build** carries `icu` (`duckdb_extension_load(icu)`) so the test binary can exercise the
  settings; a deployed duckdb autoloads it.

## Enforcement & security

- Fail-closed at the gate: every `SET` not matching name ∧ scope ∧ session ∧ constant is refused
  with a message that says which of the four it failed.
- A gateway connection cannot be polluted: without `session_connection` even a listed setting is
  refused, so a prefix-per-statement deployment never carries state between principals.
- No new data path: the two settings change rendering, not resolution, reading or cost; the value
  is a constant; `current_setting` stays denied to principals (the door reads it on their behalf
  only for the two listed names).
- Golden rule untouched: no parameters added; the SET statement passes through unchanged when
  admitted.

## Testing

- `test/sql/acl_client_settings.test` — the refusals through a prefix: an unlisted name (`SET`,
  `RESET`, `SET VARIABLE`), a listed name without a session, `SET GLOBAL`, and the word `SET` in a
  string left alone.
- `test/cpp/test_acl_session.cpp` — the positive path on a live session: `SET TimeZone` renders a
  `TIMESTAMPTZ` in Tokyo, `RESET` returns to the server's zone; unlisted / GLOBAL / non-constant
  refused on the session too.
- `test/e2e/flight/adbc_client.py` — the real ADBC driver sets
  `adbc.flight.sql.session.option.TimeZone` on connect and reads a `TIMESTAMPTZ` in that zone.

## Alternatives considered

- **Allow SET through the gateway prefix too**: rejected — the gateway shares connections; a
  per-statement `SET` is exactly how one principal's zone becomes another's wrong answer. A gateway
  that wants per-client settings gives its clients sessions (spec 040).
- **A broader allowlist (`search_path`, `preserve_insertion_order`, …)**: rejected for now —
  `search_path` changes resolution; the rest are not rendering. Each addition is a spec.
- **Storing the setting in the session record and injecting it**: rejected — duckdb's own
  per-connection setting is the mechanism; a session IS a connection (spec 050).

## Follow-ups

- The in-statement half of the session-identity sweep (answering `current_setting('TimeZone')`
  under the principal for the listed names) — the door already answers it over the protocol.
- quack's client-side session options, if quack ever grows a settings RPC of its own.
