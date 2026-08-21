# Spec 041: the quack door

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

quack is DuckDB's own client/server protocol, and it already exposes the two seams a policy layer
needs: an authentication function called once per connection, and an authorization function called per
statement **whose VARCHAR return replaces the SQL that is executed**. So serving clients under the ACL
is not a server we write — it is two thin functions over the session contract of spec 040, a denylist
for quack's own surface, and a bootstrap that refuses to start an instance a client could step out of.

Everything below was measured against a live server built in this tree, not read out of quack's
source: the door opens, a client attaches, reads its own slice, is refused a physical name, and
streamed ingest fails closed.

## Problem

A gateway prefixes every statement today. A client that connects for itself cannot: it authenticates
once and then sends ordinary SQL. Without something in between, a served connection is either
unprefixed — and under `STRICT` refuses everything — or prefixed by a component that must be trusted
to do it on every statement, forever.

## Design

**Two functions, both thin.**

```sql
acl_quack_authenticate(session_id, client_token, server_token) -> BOOLEAN
acl_quack_authorize(connection_id, query)                      -> VARCHAR
```

`acl_quack_authenticate` verifies the client's token with `acl_session_open` (spec 040) and binds the
resulting handle to quack's `session_id`, which is the `connection_id` every later message carries.
`acl_quack_authorize` looks the handle up and returns `acl_session_sql(handle, query)` — the statement
with `ACL SESSION '<handle>'` in front of it — or NULL, which quack treats as a refusal.

Neither knows anything about roles or policy. That is the property the design of the doors rests on:
a component that prefixes and routes cannot widen access, because it never had any to give.

**quack's own functions are denied.** Loading quack registers fourteen functions and our gate is a
denylist, so today every one of them is reachable by a principal: `quack_active_connections` and
`quack_server_list` (other sessions and their SQL), `quack_query` / `quack_query_by_name` (arbitrary
SQL against another server), `quack_cancel` (another principal's running query), `quack_serve` /
`quack_stop` / `quack_clear_cache` / `quack_identify`, and `scan_data_from_quack_client` (a data
stream by id).

**`acl_quack_serve` refuses to start what it should not.** It installs the two callbacks and calls
`quack_serve` only when the instance is in a state a client cannot step out of: a policy source is
configured, `acl_allow_anonymous_admin` is off, the parser override is `STRICT`, and a server token is
set explicitly. Both callback settings are `SetScope::GLOBAL`, so one served instance serves one
policy — which is exactly "this repo is one instance, and it stays that way".

**`acl_quack_stop` closes the door and what it served.** Stopping the listener leaves every session
bound to a connection that will never come back, and nothing else can tell that they are gone — a
door is the only thing that knows it closed. quack does not tell a callback which server a connection
arrived at, so sessions cannot be attributed to one; they are swept when no quack server is left in
the instance, and with two doors open the stop says what it did rather than guessing whose sessions
to drop. One instance serving one policy is the stated scope, so that branch is a guard rather than a
feature.

**TLS is not ours.** quack listens in the clear by construction
(`QuackUri(listen_uri, /* the server will always listen without SSL */ false)`), so a served
deployment sits behind a reverse proxy. `acl_quack_serve` says so rather than implying otherwise.

### What a served client needed that a prefixed gateway never asked for

Two refusals only a live client found, both fixed here:

- **Transaction statements.** A quack client sends `BEGIN` before it reads anything, and the statement
  gate admitted only SELECT/DML/EXPLAIN/DESCRIBE — so a served connection could not even load its own
  catalog (`statement type TRANSACTION is not permitted under ACL`). `BEGIN`/`COMMIT`/`ROLLBACK` name
  no object and carry no expression: they are session control, not access, and there is nothing to
  rewrite or to gate.
- **`main.<name>` resolves.** A client that has loaded a catalog addresses tables as
  `<schema>.<table>`, and an object of the default schema is stored under a bare name — so
  `main.orders` named nothing while `orders` and `c.orders` both worked. It resolves now, with the
  qualified interpretation still winning, so a catalog actually named `main` is unaffected. This was
  spec 019's documented gap; the door made it a requirement.

### Ingest, measured

- a small `INSERT … VALUES` is pushed to the server **as a statement**, so it goes through the
  authorization function, gets prefixed, and is enforced — the row lands through the ACL;
- a bulk `INSERT … SELECT` goes down quack's `SEND_DATA` path, where the server generates
  `INSERT INTO <schema>.<table> SELECT * FROM scan_data_from_quack_client('<id>')` **unprefixed**, on
  the client's own connection. That statement names a *virtual* object, and outside the ACL virtual
  names do not exist — so it fails (`Table with name orders does not exist`) and nothing is written.

So streamed ingest does not bypass the ACL; it does not work. That is fail-closed by construction
rather than by a check, and it settles the v1 question: no stream ledger is needed for safety. One is
needed for *functionality* — and bulk loading is a large part of what quack is for — so it is a spec
of its own, with two pieces this one measured — the first of which landed here:

- **the column list has to be supplied** — and this half landed here. duckdb matches a listless INSERT
  by position against the table's *full width*, and does not match by name at all, while the client
  counts the columns spec 035 published. So a listless insert now gets the list of the principal's
  writable columns in publish order: an insert of the shape we advertised writes the columns we
  advertised, and a value too many is duckdb's own width error rather than a row nobody asked for.
  **Only where the grant assigns no values**, which is the part left open below.
- **the ingest INSERT is a projection we build, not data we let through.** Once rewritten under the
  principal it goes down `ApplyInsertPolicy` like any other insert, so the grant's injected values
  (`tenant = acl_claim('tenant')`) are *assigned* rather than taken from the client, and the predicate
  is checked where the row is written (spec 024).

Worth saying plainly, because it shrinks what looks like a large piece of work: once the generated
statement reaches the rewriter **with a principal attached**, it is an ordinary `INSERT … SELECT` and
everything above is machinery we already have. The only door-specific part is attaching the principal
to an unprefixed statement — one lookup by the stream id the authorization callback recorded before
the first row moved. The ledger is not an ingest mechanism; it is that lookup.

What is left open is precisely where the two meet. The generated ingest INSERT names no columns, and
the synthesis above declines to name them when the grant injects values — because an injection projects
the source through a subquery that names what it wants, and a source one column too wide would then
lose a column silently, which is the failure mode this layer refuses everywhere else. A client writing
by hand is simply told to name its columns; a generated statement has nobody to tell. So the ledger
spec owns both halves: the lookup that attaches the principal, and a projection built over the stream
whose width is checked rather than trusted.

(The list synthesis could not land at all until the phantom column was fixed — a grant projection over
a marker stored a column with a NULL name, and the synthesis reads that same list, so a phantom column
would have become a phantom write target. Fixed on this branch; recorded because it is the kind of
thing that returns.)

## Enforcement & security

- **A refusal at either callback is a refusal.** quack turns an error or a non-true answer from the
  authentication function into "Authentication failed", and NULL from the authorization function into
  "Authorization failed" — both fail-closed by quack's own construction (`EvaluateAuthQuery` returns
  `Value(false)` on any error).
- **The handle never reaches the client.** quack's `connection_id` does, and it is a bearer credential
  in quack's model; our handle is separate, minted by us, and only ever appears in SQL we compose.
- **A client cannot re-prefix its way anywhere.** Verified before this spec: a client writing its own
  `ACL …` after the injected prefix is refused, and an `ACL` marker in a second statement of the batch
  does not parse.
- **The callbacks run on a fresh transient connection** of quack's own making, so they cannot see or
  disturb a client's session state.

## Testing

`test/sql/acl_quack_door.test` (38 assertions) — the callbacks as ordinary SQL functions, which is all
a door has to prove: authentication true for a verified token, false for one nobody can verify and for
one from an issuer nobody defined; authorization composing the prefix for a bound connection and
refusing an unknown one; an expired session refused on the connection it was bound to;
`acl_quack_serve` refusing each condition by name; quack's own functions denied to a principal, and
the callbacks themselves out of a principal's reach.

`test/sql/integration/acl_quack_serve.test` (32 assertions, needs `ACL_QUACK=1`) — the live door in one
process, since quack is both server and client: one call opens it, a client with a verified token
reads its own slice over the socket, a physical name and an unpublished column are refused, an
unverifiable token does not get in at all, an attached catalog is the principal's, and a bulk insert
fails rather than writing around the policy.

## Alternatives considered

- **Write our own server.** quack is DuckDB's own protocol with the seams already there; a second
  implementation would be ours to keep correct forever.
- **Bind the principal to the connection instead of prefixing.** Unreachable: `parser_override` gets
  no `ClientContext` (spec 040), and it would make quack's per-connection reuse unsafe.
- **Let the operator wire the callbacks by hand.** One forgotten `SET` is an open door; the refusal to
  start is the point of having a function at all.

## Follow-ups

- **quack is pre-release**, and the callback contract is what we stand on. It is pinned by commit, and
  CI's linux job builds with `ACL_QUACK=1` and runs the live round trip — so a contract change arrives
  as a red build on the next PR rather than as a surprise on the machine that happens to build it.
- **A stopped listener keeps answering for a while.** Measured: after `quack_stop` the server is gone
  from `quack_server_list()` and a fresh process refuses the port, but a listener whose client still
  holds a pooled connection went on answering. So closing sessions and closing the socket are not the
  same event, and only the first is ours. Upstream's, and worth knowing before anyone relies on stop
  as a security boundary rather than as an operation.
- **A quack client cannot enumerate the attached catalog**: `QuackSchemaCatalogEntry::Scan` is a `TODO`
  in quack, so `duckdb_tables()` over the attached catalog is empty while reads work. Upstream's.
- **Streamed ingest** — the stream ledger, if someone needs bulk loading through this door.
- **A type only the server knows** still makes the synthesized DDL unbindable for a client
  (`design/010-serving-clients`); unrelated to the door itself but reachable through it.
