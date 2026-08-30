# Backlog — the single-node mode, complete

Compiled 2026-08-30 after specs 050/051 landed, from the follow-up sections of specs 044-051 and the
local design notes. The goal of this phase: **one node, no cluster, everything works** - the front
(reverse proxy, bootstrap manager) is a separate repository, sessions stay node-local by design
(nodes know nothing of each other; the shared-session-backend idea of spec 040 is dropped).

Ordered: security and integrity first, functional completeness second, optimisations last.

## A. Security / integrity

1. **The leak audit** (owed before anything ships - design/ROADMAP "After the servers land").
   A spec-shaped inventory: surface → who answers it → what a principal gets → the test that pins it.
   At least: metadata surfaces beyond the replaced ones (whatever a loaded extension registers - the
   function gate is a denylist, and its failure mode is the name nobody wrote); **error and plan
   text** (`EXPLAIN` prints physical names, binder errors quote physical columns - what a refusal
   teaches has never been audited); server-level answers that bypass the prefix (`GetSqlInfo` is
   server metadata by design, prepared-statement schemas); session state and secrets. Inventory
   first, code second.
2. **Uniqueness on `relations(vcat, vname)`** - RESOLVED by verification (2026-08-30): the managed
   schema already declares `PRIMARY KEY ("vcat", "vname")` on `relations` (spec 034,
   policy_schema.sql), so the concurrent record write the spec-051 review worried about fails on
   the key at write time - fail-closed, last-writer never wins. Kept on the list so the item does
   not resurface; nothing to build.
3. **TLS on the Flight door** (spec 045 deferral): the door binds localhost only until it lands.
   A single node serving clients directly - no front in this phase - needs either TLS of its own
   (Arrow supports it natively) or a written decision that a reverse proxy is required equipment.

## B. Functional completeness

4. **Transactions on the held connection** (specs 047/050 deferral): `BeginTransaction` RPC is
   NotImplemented; a SQL `BEGIN` spans RPCs since spec 050 (as it always has on quack) and ingest
   refuses to run inside one. Decide and spec the real contract instead of the current honest
   patchwork.
5. **Telling a client why its session ended** (spec 044 follow-up): expired, swept, closed and
   never-existed are one NULL today.
6. **Temp objects in the columns surfaces and `SHOW ALL TABLES`** (spec 050 deliberate exclusions) -
   when a tool turns out to need them.
7. **`GetXdbcTypeInfo`** (spec 046 follow-up): not implemented; some drivers degrade without it.
8. **Bulk ingest for quack** - decided 2026-08-30: quack gets a real ingest path of its own, not a
   "Flight-only" note. quack's unprefixed `SEND_DATA` stays fail-closed by construction (spec 042);
   the shape to design from is the staging pattern the Flight door proved - `temporary` staging on
   the client's own persistent connection, promotion as ordinary SQL under the grant.

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
