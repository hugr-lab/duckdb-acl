# Spec 050: the session is a connection, and temp tables live in it

- **Status**: implemented
- **Date**: 2026-08-30
- **Author**: hugr-lab

## Summary

The Flight door has opened and closed a session inside every RPC since spec 045. That made a session
a name for nothing - `acl_session_count()` always answered zero, and no client resource could outlive
a single call. This spec makes a session **the client's connection**: identified by the protocol's own
cookie, backed by a duckdb `Connection` the door holds for the session's life, and ended by the idle
sweeper, the token's `exp`, the driver's `CloseSession`, or the door stopping. On that foundation,
**session temp tables** become native duckdb temp objects on the held connection - created under a
`temp` capability, resolved by the rewriter, and reclaimed by duckdb when the connection closes. This
is also the connection a future transaction will live on. quack already works this way (one
persistent connection per client); this brings the Flight door level with it.

Supersedes the reverted milestone-2 of spec 049 (the `_acl_staging` design) and the reverted 047
amendment; the full rationale and the measurements behind every choice are in design/015.

## Problem

Two gaps, one root:

- **A per-RPC session cannot own anything.** Spec 049's `temporary = true` ingest, and session temp
  tables generally, need a place that lives across a client's statements. The M1 review confirmed the
  hand-managed `_acl_staging` workaround was fragile (parse-time side effects, name collisions, an
  unbounded graveyard, orphaned bytes on stop) precisely because it re-implemented, badly, what a
  connection already does.
- **The cookie-session seam the reverted milestone-2 added was under-designed** (review findings F1,
  F2, F4, F5, F9): a substring cookie match, an unbounded Arrow session store, a weak cookie RNG, a
  subject-less principal fingerprint, and an idle clock refreshed before the token was verified.

The root is that spec 045 declared sessions per-RPC, reasoning from a port-reuse hazard that condemns
*peer*-bound sessions, not sessions as such.

## Design

### A session is a cookie-identified connection

- **Identity: the protocol's cookie.** Arrow's `ServerSessionMiddleware` (`arrow_flight_session_id`)
  is installed on the served options; the id generator is our CSPRNG (`MintHandle`, not mt19937 -
  F4). A call that returns the cookie reuses the connection's session; a call without it gets a
  per-call session closed on the way out (the cookie-less degradation - single-call RPCs, including
  append ingest, still work; a session resource honestly refuses on the next call). The cookie header
  is parsed by NAME, matching Arrow's own `ParseCookieString`, never by a substring of its value (F1).
- **The token stays the authority of every call.** The cookie only selects a session, and only one of
  the **same principal**. The match is `PrincipalFingerprint`, which gains the token's **subject** so
  two different users sharing roles+claims are not one session (F5). A cookie presented with a
  different principal's token closes the old session and opens a fresh one; a refreshed token of the
  same principal continues it. The token is verified **before** the session's idle clock is touched
  (F9). An unverifiable token falls through to the honest refusal it always earned, cookie or not.
- **Our handle never leaves the server.** It rides inside the middleware session as an option; the
  client sees only the opaque cookie. `Get/SetSessionOptions` stay `NotImplemented`, so the handle is
  never externally addressable.
- **Arrow's session store is bounded.** Arrow inserts a session on every call and never evicts it
  itself (its "temporary workaround"); the door keeps the factory reference and calls its
  `CloseSession(id)` whenever it closes ours - transient calls at scope end, `CloseSession`, and the
  sweep - so the store cannot grow without bound (F2).

### The held connection

- The session record owns a `unique_ptr<Connection>`, created lazily on the session's first statement
  and held until the session ends. Statements of the session **execute on it**, serialised by a
  per-session lock (the reservation pattern, generalised). Its cost is ~7 KB idle (measured,
  design/015 §7); it consumes no thread (pooled per active query) and no source connection (ATTACH is
  instance-wide).
- A ticket/prepared reservation is prepared on the **session's** connection rather than a fresh one,
  so a temp table a statement creates is visible to the statement that reads it. Ownership is still
  the principal fingerprint; the connection is the session's.
- On session end (idle / `exp` / `CloseSession` / door stop) the connection is destroyed and duckdb
  reclaims every temp object and rolls back any open transaction - no graveyard, no burial, no drain.
- **One clock rules the connection's life: the session's.** The door's connection sweep drops an
  entry only when the store says the session is dead; the connection deliberately has no idle clock
  of its own, because the metadata RPCs keep a session warm without executing on its connection, and
  a second clock diverging there dropped temp tables under a live session (PR #60 review, finding 1).
- **A client's own SQL `BEGIN` spans RPCs now**, exactly as it always has on quack - the rewriter
  passes transaction control through, and the connection persists. Protocol-level transactions stay
  `NotImplemented`; ingest refuses to load inside a transaction it would not own (below).
- **quack** is unchanged: it already holds one persistent `QuackConnection` per client. Temp is native
  on it; we only authorise.

### Temp tables, resolved without a catalog scan

`CREATE TEMP TABLE` lands natively in the connection's private temp catalog (per-connection by
construction - another session cannot see it). The rewriter must let a temp name through to native
resolution while still refusing an unknown *physical* name. It cannot read the temp catalog the usual
way: `ParserOptions` carries no `ClientContext`, and a live `Catalog::GetEntry` during the statement's
own parse throws "no active transaction" (probed), while a *separate* pool connection cannot see the
temp at all (probed). Two mechanisms, by door:

- **Flight (we own the Prepare call site):** the door stashes the held connection's `ClientContext*`
  in a thread-local before `Prepare`; the rewriter reads the connection's temp table names directly
  via `DuckCatalog::ScanSchemas` + `DuckSchemaEntry::Scan` - the **no-context, no-transaction**
  overloads (committed entries). Measured **~70 ns**, independent of attached-catalog size (immune to
  a 200k-table source). Authoritative: a bare name that is a temp is rewritten to `temp.main.<name>`;
  one that is neither virtual nor temp keeps today's `Deny("no access")`.
- **quack (Prepare is quack's):** no thread-local reachable, so the **temp-qualify fallback** - a
  bare name not found virtually, under the `temp` cap, is rewritten to `temp.main.<name>`, which binds
  only against the private temp catalog and can never reach a physical table (probed: `temp.main.x`
  does not find physical `x`; `ATTACH ... AS temp` is refused by duckdb). Message-only downside
  ("does not exist" vs "no access"); a temp-qualified miss is flat ~0.3 ms regardless of catalog size
  (measured), because qualifying to `temp` confines duckdb's suggestion search.

One rewriter rule covers both: *executing ClientContext available -> authoritative direct lookup;
else -> temp-qualify fallback.* Both require the `temp` capability; without it, today's `Deny` stands
and every existing test is unchanged.

### Rules

- **`temp` is an explicit capability** on the MAIN catalog grant, never in the unstated-caps default
  (spec 012's rule). `CREATE TEMP TABLE` is admitted by the statement gate only under it.
- **Symmetric for DML and DROP**: INSERT/UPDATE/DELETE/MERGE/DROP of a temp name take the same
  resolution - which is why the reverted parse-time DROP side effect (F6) does not return.
- **Already-qualified** `temp.x` / `temp.main.x` passes through untouched.
- **Anti-shadow**: a virtual name always wins bare-name resolution; `CREATE TEMP` of a name that
  resolves as a granted virtual object is refused for clarity.
- **Catalog inclusion**: the table listings - `SHOW TABLES`, `information_schema.tables`,
  `duckdb_tables`, and the Flight catalog RPCs (`GetTables`), which run on the session's own
  connection for exactly this reason - list the session's temp objects for that session only (via
  the same direct read); `DESCRIBE <temp>` needs no listing row, it goes down the read path.
  Deliberately NOT listed: the columns surfaces (a temp's columns are read through DESCRIBE) and
  `SHOW ALL TABLES` (its shape carries column arrays the direct read does not produce) - follow-ups
  if a tool turns out to need them. Flight only (needs the executing context); quack's native temp
  already shows in its own catalog.

### Ingest `temporary = true` (spec 049 milestone 2, completed here)

Composes `CREATE TEMP TABLE <name> AS SELECT * FROM arrow_scan($1,$2,$3)` on the held connection
instead of the `_acl_staging` scratch; the client then merges or copies from `<name>` as ordinary
SQL. Refused without the `temp` cap, and on a cookie-less (transient) call, which has no session to
hold the temp - the honest refusal spec 049 promised. Modes: `create` composes the CREATE TEMP,
`replace` its OR REPLACE form, `append` the INSERT aimed at `temp.main.<name>` (a target never
created is the bind's own error); `create_append` is refused as ambiguous. The composed CREATE rides
the same `ACL INGEST` prefix as the append INSERT - the prefix admits exactly those two statement
shapes and nothing wider - and goes through the same rewriter gate as a client's own CREATE TEMP:
the capability, the anti-shadow rule, the arrow_scan exemption only this prefix carries.

### Fleet-management seams (for the BUSL front, design/015 §8)

Three admin-scoped functions, reached through the passthrough admin door (no private channel):
`acl_node_status()` (readiness, memory/spill, live sessions, applied/target config version),
`acl_sessions()` (the live sessions on this node - admin-only), `acl_session_kill(handle)`.

## Enforcement & security

- Fail-closed throughout: an unverifiable token is refused whether or not a cookie is present; a
  cookie of a different principal never joins a session; a name that is neither virtual nor a temp of
  the caller's own connection is refused, never resolved against physical.
- The cookie is a per-viewer bearer credential, minted by our CSPRNG, and selects only same-principal
  sessions; it cannot widen what the token grants.
- Temp is per-connection by construction, so no principal can reach another session's temp through any
  surface; the metadata listing is filtered to the caller's own connection.
- The golden rule holds: temp resolution is a pure AST rewrite (or a pointer read); it adds no query
  parameter.
- `temp` is explicit and never inherited from unstated caps.

## Testing

- `test/cpp/test_acl_session.cpp` extended (a runtime handle cannot be spliced into sqllogictest): a
  cookie reuses a session across calls; a different-principal token opens a fresh one and closes the
  old; an unverifiable token refuses cookie or not; the idle clock is not advanced by an unverified
  call; `CloseSession` ends it and needs the token.
- `test/sql/acl_temp.test`: the fallback (quack-shaped) path end to end - sqllogictest has no
  executing context, exactly like quack: the `temp` cap gates CREATE TEMP, bare names resolve into
  the private temp catalog, `temp.main.x` passes through, a miss fails inside temp and never against
  physical, anti-shadow refuses a temp over a granted name, DML/DROP are symmetric, and every
  refusal a capability-less role had is unchanged. (The thread-local seam is unreachable from
  outside the extension, so the planned cpp unit became the e2e below - proven against the real
  door rather than a re-implementation of its call site.)
- `test/e2e/flight/run.sh`: the authoritative path against the served door - CREATE TEMP through the
  update wire on a cookie session, resolved by a later read of the SAME session, listed by the
  session's own `SHOW TABLES`; another connection of the same principal is refused with "no access"
  (the door *knows* that session's temp catalog is empty); a different principal on a stolen cookie
  (F5) earns nothing, and the re-authentication ends the hijacked session, temp and all; DROP is
  symmetric; the raw ingest wire stages with `temporary` and reads back on its session.
- `test/e2e/flight/adbc.sh`: the real driver (cookie middleware on, so a connection IS one session)
  drives `adbc_ingest(temporary=True)`, reads its own staging table, moves the rows into the granted
  table with plain `INSERT ... SELECT` under every rule the grant carries, and a second connection
  of the same token cannot see the staging table.

## Alternatives considered

- **Per-session temp-name set refreshed via `duckdb_tables()`** - rejected: that scan's filter
  pushdown is limited and walks the physical catalog (painful at 200k tables). The direct DuckCatalog
  read is ~70 ns and temp-bounded.
- **`_acl_staging` logical tables (the reverted milestone-2)** - rejected: re-implements, badly, what
  a connection already does; every one of its review findings dissolves under native temp.
- **Pin a connection only on demand** (borrow from a pool for plain statements, pin when a temp or
  transaction appears; design/010 §3.6) - the right long-term shape for BI-idle fleets, but an
  optimisation over always-hold, which at ~7 KB/idle is cheap enough for v1. Left as a follow-up.

## Follow-ups

- Pin-on-demand pooling (above).
- Transactions on the held connection (deferred until after the cluster release; the guard is already
  in place in the ingest path).
- Spec 051: `create`/`drop` into a live-alias home and typed `CREATE TABLE ... AS`/`CREATE OR REPLACE`
  through spec 016's machinery, plus closing the OR-REPLACE-without-`drop` hole probed on 2026-08-30.
