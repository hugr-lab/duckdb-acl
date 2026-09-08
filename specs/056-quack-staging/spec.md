# Spec 056: bulk staging on the quack door - a granted schema, not a server temp

- **Status**: implemented
- **Date**: 2026-08-30
- **Author**: hugr-lab

## Summary

The single-node backlog asked for "a real ingest path of its own" for quack, shaped after the staging
pattern the Flight door proved (spec 050: bulk into temporary staging, promotion as ordinary SQL).
Working it out found two things. First, **bulk ingest into granted tables has worked on quack since
spec 042** - the drain statement's recovered principal enforces capability, column list, predicate and
injection on every streamed row. Second, **the Flight door's server-side temp staging is unreachable
from a quack client by construction**: a quack client speaks through `ATTACH ... (TYPE quack)`, its
own `CREATE TEMP TABLE` lands in the *client's* local temp catalog, and duckdb cannot create a
temporary object inside an attached catalog - so there is no syntax by which the client could address
the server connection's temp catalog. What composes instead - out of machinery that already existed -
is staging in a **granted schema**: `CREATE` into a schema granted `create` (specs 016/051), the bulk
drain into it (spec 042), promotion as ordinary SQL under the target's grant, `DROP` under the
schema's `drop`. This spec records that decision and pins the whole round trip live.

## Problem

The backlog item assumed staging still needed building for quack. It did not - but nothing proved the
composed flow end to end, the choice between "granted schema" and "server temp" was undocumented, and
CLAUDE.md still described `SEND_DATA` as failing outright (true in spec 041, superseded by 042).

## Design

Nothing new is built. The decision:

- **quack's staging home is a granted schema** (a live alias over a physical schema, granted
  `select, insert, create, drop`). The staging table is real and private only by the schema's grant -
  which is the honest statement of what quack can offer, since per-connection temp is not addressable
  through an attached catalog.
- **Server-side temp staging remains the Flight door's** (spec 050): the Flight client executes on the
  session's held connection directly, so `CREATE TEMP` and ingest `temporary=true` land there. The two
  doors offer the same pattern at the same guarantees except locality: Flight's staging vanishes with
  the session; quack's staging is dropped by the client (or cleaned by an operator) - the price of a
  protocol that cannot address the connection's temp catalog.
- A quack client's local `CREATE TEMP TABLE` is its own business and never reaches the server - no
  change, recorded for clarity.

## Enforcement & security

Unchanged - that is the point. Every leg of the flow runs machinery whose enforcement is already
specified and tested: the CREATE under `create` (spec 016, conflict rules of 051), the drain under
the recovered principal (spec 042 - the whole-set promotion of mixed tenants is refused where the
value is written, and nothing of it lands), the promotion under the target's caps/RLS/injections, the
DROP under `drop`.

## Testing

`test/sql/integration/acl_quack_staging.test` (31 assertions, needs a quack build) - the live round
trip through a served door: the client creates `remote.stage.load` through the door, bulk-streams
5000 mixed-tenant rows into it (a genuine `SEND_DATA` drain - the payload is client-side), reads the
full staged set back; whole-set promotion into the RLS-confined target is refused with nothing
stored; the principal's own slice promotes (2500 rows) and reads back as exactly its slice; the
staging table drops through the door.

## Alternatives considered

- **Making server temp addressable from quack** (a pseudo-schema, a session function that redirects a
  name) - rejected: it would invent syntax duckdb does not have, for a difference (auto-cleanup) the
  session sweeper does not need and an operator can get with a granted schema plus a cleanup job.
- **A quack-side `temporary` flag in the drain protocol** - rejected: `SendDataRequestMessage` is
  quack's wire format, not ours to extend, and the drain already has a home for the data the client
  can name.

## Follow-ups

- None for the door. If quack ever grows a raw-SQL channel that executes verbatim on the server
  connection, server temp becomes expressible and spec 050's temp machinery would serve it unchanged
  (the quack fallback path already resolves bare temp names).
