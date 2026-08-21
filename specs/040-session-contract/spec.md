# Spec 040: a session is a handle, and one contract serves every door

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

Today a principal arrives in the text of every statement, as `ACL ROLE "r"` or `ACL TOKEN '<jwt>'`.
A door that serves clients — quack, and the Flight SQL server after it — needs to turn a token into a
principal **once**, at connect, and then attach it to every statement that connection sends. This adds
that: `acl_session_open(token)` mints an opaque handle, `acl_session_sql(handle, sql)` returns the SQL
to execute with the handle prefixed, `acl_session_close(handle)` ends it, and a new prefix form
`ACL SESSION '<handle>'` resolves it. Three functions and one prefix — no server, no sockets, and
every property testable through plain SQL.

## Problem

Both doors need the same three things, and neither can get them from what exists:

- **Verify once, use many times.** Quack calls an authentication function on connect and an
  authorization function per statement; a Flight SQL server authenticates on handshake. Re-verifying a
  JWT signature on every statement is work we can avoid, and re-sending the JWT in the query text is
  worse than avoidable — it puts the raw token into `EXPLAIN` output, error strings, and quack's own
  structured log.
- **A door must not hold policy.** The cleanest shape found while designing the servers
  (`design/010-serving-clients`) is that a coordinator or a door prefixes and routes, and never
  decides: it should not need to know how a token maps to roles, only that something opaque stands for
  a verified principal.
- **Nothing is testable without a server today.** Everything about identity, expiry and refusal
  currently arrives through a prefix a gateway writes. A contract makes those properties reachable
  from a `.test` file.

## Design

**Three functions, and they are the whole outward contract.**

```sql
acl_session_open(token)        -- VARCHAR handle, or NULL if the token does not verify
acl_session_sql(handle, sql)   -- the SQL to run, prefixed; NULL if the session is not usable
acl_session_close(handle)      -- ends it; idempotent
```

`acl_session_sql` returns `'ACL SESSION ''<handle>'' ' || sql` for a live session and NULL otherwise —
so a door's whole job is "call this, run what it returns, refuse if it is NULL". Quack's authorization
function is a one-line wrapper over it; our Flight SQL server calls it directly; a coordinator that
routes rather than executes calls it and forwards the string.

**`ACL SESSION '<handle>'` is a fourth prefix kind**, parsed exactly as `ROLE` and `TOKEN` are, and
carrying the same markers after it: a `passthrough` principal still writes `ACL SESSION 'h' ACL NATIVE
<sql>`, a `manage` one still writes `ACL SESSION 'h' ACL <mgmt>`. Resolution differs only in where the
principal comes from — a handle lookup instead of a role name or a token verification.

**A handle is minted by the store and opaque to us.** Cryptographically random, so a client cannot
forge or guess one; never parsed; and it is what the prefix carries instead of the JWT, which is the
point (§Problem). The session record holds the principal (roles and claims, as spec 007 resolved
them) and the token's `exp`.

**Expiry is checked on every use, not only at open.** `acl_session_sql` refuses a session past its
`exp` with a distinguishable answer, so a door can tell a client to reconnect rather than retry. A
policy change needs nothing: rights are resolved per statement against the store, as they already are
— only identity is cached in the handle.

**Where sessions live is a source, like policy.** This spec ships the in-memory backend: a map from
handle to record, per `DatabaseInstance`, behind a mutex, swept on close and on expiry. The seam is
shaped so the catalog and function-driver backends from `design/010-serving-clients` §4.1 can follow
without changing the contract — that is what lets a cluster own session state without a private
channel. Not in this spec: the shared backends, and the portability predicate they exist for.

## Enforcement & security

- **Fail-closed at every step.** A token that does not verify gives NULL, not a session. An unknown,
  closed or expired handle gives NULL from `acl_session_sql` and a refusal from the prefix. A door
  that forgets to check NULL prefixes nothing, and an unprefixed statement is refused under `STRICT`.
- **A handle is a bearer credential**, so where its randomness comes from is a decision, not a
  detail. It uses `std::random_device` — the OS CSPRNG on both supported platforms — rather than
  duckdb's own utilities, and the self-review is why: `RandomEngine` seeds from the clock off Linux,
  and the encryption util refuses to generate randomness unless OpenSSL arrived with httpfs (its
  mbedTLS fallback demands `force_mbedtls_unsafe`). Reading `DBConfig::encryption_util` directly, as
  the first cut did, silently took the clock-seeded path in every ordinary build. The handle is never
  derived from the token, never logged by us, revocable by `acl_session_close`, and useless outside
  this instance.
- **A client cannot mint or borrow one.** Verified rather than assumed: under a principal all three
  functions are refused by the gate (`function "acl_session_open" is not allowed`), so a principal can
  neither mint a session, nor compose a prefix, nor close somebody else's. And a client writing `ACL SESSION 'x'` into its own query text is refused the same
  way a doubled prefix is today — the injected prefix is the only one that binds.
- **No new query parameters** (the golden rule): the prefix is text, and the statement after it is the
  client's own.
- **Per-instance state**, reached through the same `PolicyStore` the parser already has — no process
  globals, so two instances in one process never share sessions.

## Testing

`test/sql/acl_session.test` (33 assertions):

- a verified token opens a handle of 128 bits of hex, and one that does not verify gives NULL rather
  than an error carrying detail;
- `acl_session_sql` composes exactly `ACL SESSION '<handle>' <sql>`;
- an unknown handle and a closed one give NULL, closing twice is not an error, and two sessions from
  one token are two sessions;
- **expiry is judged on every use**: a token whose `exp` is in the past, opened with a wide
  `acl_jwt_clock_skew` and then judged with none, stops composing;
- the prefix refuses an invented handle by name (`session unknown`), still demands a quoted value, and
  a client writing its own `ACL SESSION` inside a query does not become another principal.

**`test/cpp/test_acl_session.cpp`** (17 checks) carries what a `.test` file cannot: the handle is
minted at runtime, and the prefix is text scanned before the parser runs, so no test file can splice
a value into it. It pins the property that matters most — `ACL SESSION '<handle>'` answers exactly as
`ACL TOKEN '<jwt>'` does, claims-driven RLS included — plus running `acl_session_sql`'s own output as
the query, a closed handle refused by both the composer and the prefix, and two instances in one
process not seeing each other's sessions.

## Alternatives considered

- **Keep sending the JWT in the prefix.** No new grammar, and re-verification per statement gives
  expiry for free — but the raw token then travels in every query string, through `EXPLAIN`, error
  text and any query log a deployment adds.
- **Bind the principal to the connection instead of the statement.** The obvious design, and
  unreachable: `parser_override` receives `(info, query, options)` and no `ClientContext`, so the
  resolver cannot know which connection it is on. It would also make a pooled connection unsafe, which
  is what `design/010-serving-clients` §3.6 depends on.
- **Let each door invent its own.** Two implementations of identity, diverging, each with its own
  tests. The contract exists precisely so a door proves one thing: that it calls it.

## Follow-ups

- The **shared session backends** (catalog table, function driver) and the portability predicate a
  cluster needs — `design/010-serving-clients` §4.1 and §10.2.
- **Revocation** beyond `exp` and an explicit close: a shared backend can mark a session dead, bounded
  by the local cache TTL, the same way a policy change already is.
- **What a door reports about a refused session** — "expired" and "unknown" are different for a
  client, and NULL alone does not say which. `SessionPrincipal` already distinguishes them; only the
  SQL surface flattens it.
- **Nothing sweeps abandoned sessions.** An expired record is erased when it is next looked up, and a
  closed one when it is closed — but a door that opens sessions and then forgets them leaves entries
  in memory until something asks for each. Bounded in practice by a door closing on disconnect;
  unbounded if one does not. A periodic sweep, or a cap, belongs with the shared backends.
