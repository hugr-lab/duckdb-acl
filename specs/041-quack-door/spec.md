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
unprefixed — and an unprefixed statement is not refused, it simply runs natively with the operator's
rights, which is worse — or prefixed by a component that must be trusted
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
- a bulk `INSERT … SELECT` goes down quack's `SEND_DATA` path, and that path **is not the statement
  path**. quack asks the authorization function about it with a statement it never executes —
  `INSERT INTO <schema>.<table> VALUES (NULL)`, generated purely so a policy layer can decide — and
  reads only whether the answer is NULL. It then generates the real statement,
  `INSERT INTO <schema>.<table> SELECT * FROM scan_data_from_quack_client('<id>')`, **unprefixed**, on
  the client's own connection.

The first version of this spec called that fail-closed, because the generated statement names a
*virtual* object and outside the ACL virtual names do not exist. **That was wrong, and the correction
is the important part of this section.** Two mistakes stood behind it:

- **an unprefixed statement is not refused.** `STRICT` governs whether duckdb consults an override at
  all, not whether every statement must carry a prefix — so a statement we decline runs natively, with
  the operator's rights and no policy. Declining is right for the console and the bootstrap; it is
  exactly wrong for a statement a client caused.
- **the name resolves more often than the test's layout suggested.** The generated INSERT is resolved
  in the server's *default* catalog. The integration test kept its physical tables in an attached
  catalog, so the name found nothing and the write failed — a property of that layout, not of the
  design. Put the physical table in the default catalog under the name the object publishes, and the
  statement binds.

Measured on that layout, with the object publishing its full width: a client bulk-inserted **5000 rows
carrying a tenant its own grant predicate forbids**, into the physical table, with no RLS, no injected
claim, and no capability check that meant anything — the prefixed VARCHAR we returned for the probe is
non-NULL, so quack read it as "allowed" while nothing enforced it. Where the widths disagreed the write
was stopped only by `table orders has 3 columns but 2 values were supplied`, which is duckdb counting,
not us deciding.

**So it is refused, in two places.** The probe is answered NULL — quack turns that into
"Authorization failed" and no data moves at all. And the generated statement is refused where every
unprefixed statement passes, in the parser override itself: a statement that *calls*
`scan_data_from_quack_client` carries no principal and cannot be enforced, so it does not run. The
second is the security boundary — what writes is that statement, and it names that function every time,
whatever quack later does to the question it asks first. The first is the good error message.

Streamed ingest therefore does not work, deliberately and by a check rather than by an accident of
layout. Making it *work* is a spec of its own — bulk loading is a large part of what quack is for —
with two pieces this one measured, the first of which landed here:

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
to an unprefixed statement — and the stream id makes that nearly free. quack builds it as
`connection_id + ":" + uuid` (`QuackStreamRegistry::MakeId`) and passes it to the scan function, so the
statement that refuses to run today *already carries* the connection id that
`acl_quack_authenticate` bound to a session. The ledger is not a new table and not an ingest mechanism;
it is reading the principal back out of the id at the place that currently throws.

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
- **Answering a question quack asks is not the same as enforcing the statement it runs.** The ingest
  probe is the one place where the two came apart, and it is the reason for the fence in the parser
  override: what enforces a statement is the rewrite, so a path that does not carry our rewritten SQL
  must be refused rather than authorized. Anything a future quack asks about but executes itself falls
  under the same rule.
- **The other message types were audited for the same shape**, since the bug was not that this one
  path was wrong but that we had not asked the question of each. quack handles nine:
  `CONNECTION_REQUEST` calls the authentication function; `PREPARE_REQUEST` calls the authorization
  function **and executes what it returns**, which is the path the whole door rests on;
  `SEND_DATA_REQUEST` is the one above. The remaining six — `FETCH_REQUEST`, `FINALIZE`,
  `CANCEL_REQUEST`, `DISCONNECT_MESSAGE`, `ACKNOWLEDGEMENT`, `HEARTBEAT_REQUEST` — carry no SQL and
  touch only the state of the connection they arrive on, which the server resolves per message from
  the connection id. So exactly two message types carry SQL, and both are accounted for. This list is
  a snapshot of a pre-release protocol: a new message type is a new question, not a new answer.
- **The fence is blunt on purpose.** It refuses any unprefixed statement that *calls*
  `scan_data_from_quack_client`, without parsing. The parenthesis is required because the resolver
  embeds the name it is looking up as a literal in its own catalog SQL — found by this very test — so
  a bare occurrence proves nothing while a call is what a generated ingest statement always is. A
  client cannot author that text: the statement is the server's own.
- **The handle never reaches the client.** quack's `connection_id` does, and it is a bearer credential
  in quack's model; our handle is separate, minted by us, and only ever appears in SQL we compose.
- **A client cannot re-prefix its way anywhere.** Verified before this spec: a client writing its own
  `ACL …` after the injected prefix is refused, and an `ACL` marker in a second statement of the batch
  does not parse.
- **The callbacks run on a fresh transient connection** of quack's own making, so they cannot see or
  disturb a client's session state.

## Testing

`test/sql/acl_quack_door.test` (45 assertions) — the callbacks as ordinary SQL functions, which is all
a door has to prove: authentication true for a verified token, false for one nobody can verify and for
one from an issuer nobody defined; authorization composing the prefix for a bound connection and
refusing an unknown one; an expired session refused on the connection it was bound to;
`acl_quack_serve` refusing each condition by name; quack's own functions denied to a principal, and
the callbacks themselves out of a principal's reach. Plus both halves of the ingest refusal: the probe
answered NULL in the shapes it can arrive in, an ordinary insert still composed, and the parser fence
refusing a statement that calls the stream scan.

`test/sql/integration/acl_quack_ingest_denied.test` (25 assertions, needs `ACL_QUACK=1`) — the bypass,
on the layout that made it real: the physical table in the server's default catalog under the published
name, the object publishing its full width, and the role confined by a predicate. A bulk insert is
refused, the table is unchanged and carries no forbidden tenant, and a small insert still writes through
the statement path — so the refusal is aimed at ingest, not at writing.

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
