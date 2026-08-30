# Backlog — the single-node mode, complete

Compiled 2026-08-30 after specs 050/051 landed, from the follow-up sections of specs 044-051 and the
local design notes. The goal of this phase: **one node, no cluster, everything works** - the front
(reverse proxy, bootstrap manager) is a separate repository, sessions stay node-local by design
(nodes know nothing of each other; the shared-session-backend idea of spec 040 is dropped).

Ordered: security and integrity first, functional completeness second, optimisations last.

## A. Security / integrity

1. **The leak audit** - DONE → spec 052. The inventory (a table in the spec) found the gate and the
   surface replacements already fail-closed everywhere but one: `EXPLAIN` printed physical names.
   Fixed by making EXPLAIN an explicit `explain` capability on the MAIN grant (refused by default,
   physical names and all); binder errors under a projection, metadata table functions,
   `sqlite_master`, settings/secrets and runtime errors were all confirmed safe. `GetSqlInfo` is
   server metadata by design; `GetXdbcTypeInfo` stays unimplemented (item 7).
2. **Uniqueness on `relations(vcat, vname)`** - RESOLVED by verification (2026-08-30): the managed
   schema already declares `PRIMARY KEY ("vcat", "vname")` on `relations` (spec 034,
   policy_schema.sql), so the concurrent record write the spec-051 review worried about fails on
   the key at write time - fail-closed, last-writer never wins. Kept on the list so the item does
   not resurface; nothing to build.
3. **TLS on the Flight door** - DONE → spec 053. `acl_flight_serve(uri, cert, key)` serves over TLS
   (`grpc+tls`) and may bind any address; `acl_flight_serve(uri)` stays cleartext-localhost. cert/key
   are inline PEM or paths read through duckdb's filesystem. A reverse proxy stays valid but is no
   longer required. mTLS is a follow-up.

## B. Functional completeness

4. **Transactions on the held connection** - DONE → spec 055. `BeginTransaction`/`EndTransaction`
   open and end a transaction on the session's connection; `FLIGHT_SQL_SERVER_TRANSACTION` is now
   `TRANSACTION`, so a driver with autocommit off (DBeaver, ADBC manual-commit) works. Savepoints
   are a follow-up.
5. **Telling a client why its session ended** - DONE → spec 054. `acl_session_reason(handle)` returns
   "live"/"expired"/"idle"/"unknown", judged read-only so it survives the NULL from `acl_session_sql`.
   Closed and never-existed both read "unknown" (no tombstone, by design).
6. **Temp objects in the columns surfaces and `SHOW ALL TABLES`** (spec 050 deliberate exclusions) -
   when a tool turns out to need them.
7. **`GetXdbcTypeInfo`** (spec 046 follow-up): not implemented; some drivers degrade without it.
8. **Bulk ingest for quack** - DONE → spec 056, and mostly it already existed: bulk into granted
   tables has worked since spec 042 (the drain's recovered principal enforces every streamed row).
   What 056 adds is the decision and the pin: quack's staging is a **granted schema**
   (CREATE/drain/promote/DROP through specs 016/042/051, proven live end to end), because a quack
   client cannot address the server connection's temp catalog through an attached catalog - the
   Flight door's server-side temp (spec 050) is unreachable from quack by construction.

## C. Optimisations / platform

9. **Pin-on-demand pooling** (spec 050 alternative): borrow a pooled connection for plain
   statements, pin one only when a temp or transaction appears. Right shape for BI-idle fleets;
   always-hold at ~7KB idle is fine until then.
10. **Windows build**: MSVC is a declared release target (CLAUDE.md); CI builds linux and macOS.
11. **Physical-PK import at `CREATE VIRTUAL TABLE`** (spec 048 follow-up, admin convenience) and
    `duckdb_constraints()` as a principal surface, if a tool reads it.

## D. Live validation - the closing item of this phase

12. **A live scenario against real client tools**: DBeaver (the Flight SQL JDBC driver), a quack
    client, and an ADBC client (python; Power BI where available) each walk one scripted scenario
    against a served node - connect, browse the catalog tree, read a slice, write under a grant,
    stage temp and promote, and every refusal reads sensibly in the tool's own UI. Scripted where
    possible (the e2e already drives the real ADBC driver), a runbook where a GUI is involved: the
    phase ends with eyes on real tools, not only on our own harnesses.

## Done recently (for orientation)

- Declared virtual keys → spec 048. Ingest append/create/replace → specs 049/051. Session =
  connection, session temp tables → spec 050. REPLACE priced as drop, record conflict semantics →
  spec 051.
