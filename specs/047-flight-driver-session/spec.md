# Spec 047: the door answers a driver's session layer

- **Status**: draft
- **Date**: 2026-08-26
- **Author**: hugr-lab

## Summary

A survey of the door through a real external client (`adbc_driver_flightsql` - the driver behind
DBeaver and Power BI; design/012, design/013 §4) drew a sharp line. Everything that is a statement
works: SELECTs, joins, DML as text with refusals arriving verbatim, the catalog tree of spec 046,
the promised schemas. Everything that is the *driver's session layer* breaks: a parameterized query,
`executemany`, `adbc_get_info`. This spec adds the two missing pieces - **prepared statements** and
a **registered SqlInfo** - and nothing else.

## Problem

Three measured failures, each in the driver's own words:

- `SELECT ... WHERE amount >= ?` → the driver only carries parameters through
  `CreatePreparedStatement`; the door answers NotImplemented, and the driver then poisons the cursor
  (`must set IngestTargetTable before bulk ingestion` on every later call). Parameterized queries -
  the way every BI tool and every ORM writes them - do not work at all.
- `executemany` → `CreatePreparedStatement not implemented`, the honest half of the same gap.
- `adbc_get_info` → the C++ base class answers `GetSqlInfo` from an **empty registry** with
  `NOT_FOUND`, and the driver refuses that outright - while tolerating `NOT_IMPLEMENTED` from a
  server that lacks the RPC entirely (measured, design/012). Being *almost* a Flight SQL server is
  worse here than not being one.

## Design

### SqlInfo: registered once, honest everywhere

`FlightSqlServerBase::RegisterSqlInfo(id, result)` fills the registry the base already serves from.
Registered at door construction, values chosen to be true rather than flattering:

| id | value |
| --- | --- |
| `FLIGHT_SQL_SERVER_NAME` | `duckdb-acl` |
| `FLIGHT_SQL_SERVER_VERSION` | the extension's version |
| `FLIGHT_SQL_SERVER_ARROW_VERSION` | the linked Arrow's version |
| `FLIGHT_SQL_SERVER_READ_ONLY` | `false` - DML as text works today, gated by capabilities |
| `FLIGHT_SQL_SERVER_SQL` / `..._SUBSTRAIT` | `true` / `false` |
| `FLIGHT_SQL_SERVER_TRANSACTION` | none supported |
| `FLIGHT_SQL_SERVER_CANCEL` | `false` |
| `FLIGHT_SQL_SERVER_BULK_INGESTION` | `false` - **flips to true in spec 049**, in the same commit
  that implements it |

The rule this encodes, learned the hard way: a wrong or half-right answer here is worse than
absence - a malformed SqlInfo *panicked* the Go driver in the spike (design/012). The registry is
answered by the base class from typed variants, so the shape cannot drift; what this spec owes is
only that the values stay true as features land.

### Prepared statements: the ticket rule, applied to a handle

The protocol's flow, and what the door does at each step - every call through the same
`UnderSession` boundary as everything else (token verified per call, session per call, exceptions
become named Statuses):

1. **`CreatePreparedStatement(query)`** - compose under the caller's session and *prepare* to learn
   the two schemas the protocol wants back (result columns; parameter types from duckdb's own
   binder). Mint an unguessable handle; store **the client's own SQL** against it - never the
   composed statement, for spec 045's reason: the prefix names a session, and each use must compose
   afresh under whoever calls.
2. **`DoPutPreparedStatementQuery(handle, param batches)`** - the client's parameter values arrive
   as Arrow record batches. They become duckdb values through duckdb's *own* conversion: the batch
   is exposed as an `ArrowArrayStream` and read back through `arrow_scan` - the exact mechanism
   duckdb's in-tree ADBC layer uses for ingest - so no second Arrow-to-duckdb type mapping exists in
   this codebase. The rows of values are stored with the handle.
3. **`GetFlightInfoPreparedStatement(handle)`** - re-prepare under the *caller* for the schema, and
   return an endpoint whose ticket is the protocol's own `PreparedStatementQuery` command. The
   command carries the handle, so - like the catalog RPCs of spec 046 - **no ticket ledger entry is
   needed**: nothing is remembered between the two calls that is not already in the handle's record.
4. **`DoGetPreparedStatement(handle)`** - verify the caller, look up the handle, compose the stored
   SQL under *the fetcher's* session, `Execute` with the stored values, stream. A handle that
   reached another principal returns **their** slice - the ticket rule of spec 045, unchanged.
5. **`DoPutPreparedStatementUpdate(handle, param batches)`** - `executemany`: execute once per
   parameter row under the caller, return the summed count.
6. **`ClosePreparedStatement(handle)`** - drop the record. `acl_flight_stop` drops them all.

State: one map, handle → {client SQL, parameter rows}, guarded by the door's lock, capped at
`MAX_PREPARED = 4096` (the ticket cap's reasoning: refuse a new one rather than evict an old one).
A prepared statement is *door* state, not session state - our sessions are per-call (spec 045) and
stay that way.

**The golden rule is why this design is short.** The rewriter adds no parameters, so the client's
`$1`/`?` are the only parameters in the composed statement, so the client's values map onto it
one-to-one with nothing renumbered and nothing injected - `PreparedStatement::Execute(values)` just
works. The C++ invariant tests of spec 002 have pinned that property for years; this is the feature
it was waiting for.

## Enforcement & security

- **A handle is not an authority.** Every call re-verifies the token; execution composes under the
  caller. Stealing a handle earns its holder exactly what their own token earns them.
- **Parameters are values, never SQL.** They travel as Arrow data, convert through `arrow_scan`, and
  bind through duckdb's parameter binding - no string ever meets the parser.
- **Fail-closed edges**: unknown handle → refusal; the cap refuses new handles rather than evicting;
  a prepare that the ACL refuses fails at `CreatePreparedStatement`, before any handle exists;
  `transaction_id` on the request → refused until transactions exist.
- **SqlInfo answers about the server, not about any principal** - the one Flight surface that does
  not pass through a prefix (spec 046 named it). The registry holds build-time constants only;
  nothing in it is derived from policy, so nothing in it can leak one.

## Testing

**e2e through the real driver** (`test/e2e/flight/adbc.sh`, skipped without the driver): the survey
matrix of design/013 §4 turned into assertions - parameterized `?` and `$1` answer the principal's
slice; `executemany` inserts land and the grant's predicate still refuses a cross-tenant row
(spec 024, already proven for text DML); `adbc_get_info` returns the registered values; a second
principal executing a stolen handle gets its own slice; the poisoned-cursor sequence from the survey
now runs clean end to end.

**The hand-encoded client** (`test/e2e/flight/client.py`) stays as-is for the unprefixed
protocol-level checks; prepared statements are exercised through the driver on purpose - the point
is what a real client does.

## Alternatives considered

- **A hand-written Arrow→Value type switch** for parameters: smaller than it looks until the first
  timestamp, and a second type mapping to keep honest. `arrow_scan` is duckdb's own path.
- **A ticket-ledger entry per prepared execution**: unnecessary - the protocol's command carries the
  handle, the handle's record carries the rest (the spec-046 "the ticket is the command" pattern).
- **Session-scoped prepared statements**: our sessions are per-call by design (spec 045); binding
  handles to them would recreate the state this door deliberately does not hold.

## Follow-ups

- **Spec 048**: declared virtual primary keys - on the object's own declaration
  (`CREATE VIRTUAL TABLE ... PRIMARY KEY (...)`, same for views and table functions), answering
  `GetPrimaryKeys` and an honest `has_primary_key`; views and references proven through the driver.
- **Spec 049**: `DoPutCommandStatementIngest` by spec 042's staging pattern; flips
  `FLIGHT_SQL_SERVER_BULK_INGESTION` to true.
- **Transactions**: `FLIGHT_SQL_SERVER_TRANSACTION` says none; `BeginTransaction` stays unimplemented
  until a spec wants it.
