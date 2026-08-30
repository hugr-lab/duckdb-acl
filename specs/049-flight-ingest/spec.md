# Spec 049: the Flight ingest — bulk loading through the door, under the policy

- **Status**: implemented
- **Date**: 2026-08-29
- **Author**: hugr-lab

## Summary

`DoPutCommandStatementIngest` is the Flight SQL bulk-load RPC: a client streams Arrow record batches
at a named table and the server returns the row count. This wires it under the policy. Unlike the
quack drain (spec 042), the Arrow stream **carries its own column names**, so the ingest is an
ordinary `INSERT <named columns> SELECT <named columns> FROM <the stream>` composed under the
caller's session and rewritten exactly as any other write — caps gate the verb, the grant's predicate
confines the rows (spec 024), injections assign what the grant owns (spec 026). The one new piece is
the source: the server reads the client's batches into an `arrow_scan` it composes itself, and to
keep a client from reaching that function with a pointer of its own choosing, `arrow_scan` joins the
denylist and the ingest gets the single-value exemption spec 042 established for its drain.

## Problem

Bulk loading is most of what a columnar wire protocol is for, and today the door answers
`FLIGHT_SQL_SERVER_BULK_INGESTION = false` and has no `DoPutCommandStatementIngest`, so an ADBC
client's `adbc_ingest` / a JDBC `executeUpdate`-of-a-stream has nowhere to land. `executeUpdate` of
*text* landed in spec 048 (`DoPutCommandStatementUpdate`); a parameterized batch landed in spec 047
(`DoPutPreparedStatementUpdate`, executemany). Ingest is the third DoPut write path and the only one
that streams raw columnar data with no SQL of the client's own.

A latent hole surfaces alongside it: `arrow_scan` is a duckdb built-in that turns three raw pointers
into a table, and it is **not** on the principal denylist (spec 041). Through the door the function
gate is a denylist, so a client may send `SELECT * FROM arrow_scan(<n>, <n>, <n>)` today; the
pointers are process-local and unpredictable, but "unpredictable" is not "closed". Ingest must use
exactly this function, so the fix and the feature travel together.

## Design

### The RPC and the shape of the write

`StatementIngest` carries `table`, optional `schema` and `catalog`, `table_definition_options`
(`if_not_exist` / `if_exists`), `temporary`, `transaction_id`, and a backend `options` map. The
reader hands a sequence of Arrow record batches with a schema whose field names are the client's own.

The server, inside `UnderSession` (the caller's live session, as every other door RPC):

1. **Refuses what it does not do**, fail-closed and by name:
   - `transaction_id` present → `NotImplemented` (transactions are deferred until after the cluster
     release — spec 048's twin refusal).
   - `temporary = true` → the staging path (milestone 2 below): a session-scoped staging table the
     client then copies or merges from with plain SQL. Until milestone 2 lands, `NotImplemented`.
   - `if_not_exist = CREATE` or `if_exists = REPLACE` → `Invalid`, with the refusal naming what is
     missing rather than a bare no: creating needs a `create` capability and a declared physical
     home (a live schema alias), replacing needs `create` and `drop` - all of which is spec 050,
     the follow-up below. Until then the target is an existing virtual relation and ingest only
     appends; `FAIL` / `APPEND` / unspecified are accepted.
2. **Reads the client's batches into an `arrow_scan`**, refusing *while reading* against a row cap
   (`acl_max_ingest_rows`, default 0 = unlimited; a bound enforced after materialization is no bound)
   — the ledger pattern from `ParamRowsFrom`, but the stream is handed to `arrow_scan` rather than
   materialized into `Value`s, so a multi-gigabyte load never sits in server RAM as a row vector.
3. **Composes the insert as the server's own text**, from the client's Arrow field names:
   `INSERT INTO <catalog>.<schema>.<table> ("a", "b", "c") SELECT "a", "b", "c"
    FROM arrow_scan($1, $2, $3)`,
   the qualified name built from whatever of `catalog`/`schema`/`table` the command supplied (a bare
   `table` resolves in the session's MAIN catalog, as a bare name does for a query). The three
   parameters are the server's stream/adapter pointers, bound by the door at execution — `POINTER`
   has no literal form in SQL text, and this statement carries no parameters of anybody else's, so
   no user numbering exists to shift and the client never sees or controls them.
4. **Prefixes it as `ACL INGEST '<handle>' …`** (the door's own composition, above) and prepares +
   executes on a call-local `Connection`. The load is **one statement**, so duckdb's own statement
   atomicity is the transaction: a refusal anywhere — a predicate violation on row N, a stream error,
   a width mismatch — fails the statement and nothing of it is stored; a retry cannot double-load.
   The returned `changed` count is the statement's row count, and it is **cross-checked against the
   rows the stream actually delivered** (GizmoSQL's lesson): a mismatch is an error, never a silently
   partial load.

Everything after step 3 is the rewriter we already have. Because the source **names its columns**,
this is the ordinary `INSERT … SELECT` path, not spec 042's positional `* REPLACE`: caps gate
`insert`; each named column must be writable (a mask/computed column is refused, spec 026); the
grant's predicate is AND-ed as a written-row check and a row outside the slice is refused where it is
written (spec 024); an injected column (`tenant = acl_claim('tenant')`) drops the client's value and
substitutes the claim by construction. A client that omits a grant-injected column has it added; a
client that sends it has it overwritten — the named injection path already does both.

### The exemption, exactly as narrow as spec 042's

`arrow_scan` and `arrow_scan_dumb` join the denylist, so no principal reaches them from SQL of their
own. The composed ingest is rewritten *under the principal*, so the gate would refuse the very
statement we are enforcing — the same bind spec 042 hit. The resolution is a flag the wire cannot
fake: a fifth prefix kind, **`ACL INGEST '<handle>' <insert>`**, composed only by the door's own C++
(never by `acl_session_sql`, which emits `ACL SESSION`). It resolves the handle to a principal
exactly as SESSION does — same expiry, same idle judgment — then sets `Principal::ingest`, admits
**exactly one statement, and only an INSERT**, and the function gate passes an `arrow_scan` call for
that principal and nothing else. A client cannot author the prefix: every door wraps client text as
`ACL SESSION '<handle>' <text>`, so an embedded `ACL INGEST …` is mid-statement garbage, and the
handle itself is server-internal — a Flight client holds a token, never the handle. Unlike spec 042
there is no client-named stream id to bind to (the pointers are the server's own text), so the flag
is a boolean carried by a prefix nobody else can compose.

### `temporary = true` — a staging table for the credential, and SQL does the rest (milestone 2)

The decided upsert flow: ingest stages, SQL copies. A `MERGE` needs its matching condition *and its
actions* (`WHEN MATCHED THEN UPDATE/DELETE …`), and both are SQL — no flag or options semantics
carries them. So the RPC's own `temporary` field creates a **staging table** and the client follows
with an ordinary text statement (`MERGE INTO target USING stage ON …`, `INSERT … SELECT`), which the
rewriter enforces as any other: `merge`/`insert` caps on the target, predicate confinement, the lot.

**The scope is the session, and the session is the connection.** The Flight door's sessions are
cookie-identified connections (spec 047's amendment, design/015), so staging lives where a session
resource belongs: in the session record, dying with it - by idle, by `exp`, by the driver's own
`CloseSession`, by the door stopping. Parallel connections of one principal are separate sessions
with separate staging; a client without cookies has no session to stage into and is refused
honestly. `PrincipalFingerprint` goes back to being what it was: the owner check on reservations.

Mechanics:

- **Physical home**: the schema `_acl_staging` in the server's own default catalog; the table is
  `<staging id>_<name>` where the id is random and minted per session — *not* the session handle,
  which is a bearer credential and must never appear in a catalog listing. A staging name itself is
  a bare identifier (letters, digits, `_`), refused otherwise.
- **Created by the server's own unprefixed CTAS** from the same `arrow_scan` source: no policy
  object is touched — the bytes are the client's own, and the table is reachable only through the
  staging map. Later `temporary` ingests into the same name append (`if_exists = REPLACE` recreates —
  it is yours; `FAIL`/`if_not_exist = FAIL` answer honestly). An explicit `catalog`/`schema` with
  `temporary` is refused: the namespace is the server's, exactly as duckdb's own ADBC driver
  documents the combination as incompatible.
- **Resolution is a fallback, never a shadow**: the rewriter looks a bare name up in the staging map
  only after catalog resolution fails, and the ingest refuses a staging name that collides with an
  object the principal can see — so a granted name always wins (design/013 §7's anti-shadowing
  rule). Reads and writes of one's own staging need no grant; `DROP TABLE <stage>` unregisters it
  and drops the physical scratch.
- **Lifetime**: idle-swept on `acl_session_idle_timeout`, the clock everything else here ages on.
  A sweep holds the store lock and must run no SQL, so the physical drops land in a **graveyard**
  that a door drains on the way into its next RPC; `acl_flight_stop` / `acl_quack_stop` close all
  staging with the sessions they served.
- **Gate**: an explicit **`temp` capability** on the MAIN catalog grant (never part of the
  unstated-caps default — spec 012's rule), checked where the staging is made. The memory store has
  no catalog grants, so `temporary` under the dev stub is refused. `acl_max_ingest_rows` bounds each
  load, and a disk-backed server database spills instead of holding the scratch in RAM.

### What a writable ingest requires (unchanged from spec 042)

- **The target is RENAME-form (writable).** A virtual object declaring `COLUMNS` is a projection and
  read-only by construction (spec 001), so a narrowed object refuses a bulk load as it refuses any
  write. A confined-but-writable target is a plain object plus a grant that states its columns and
  predicate — which is also what gives the insert a column policy to check against.
- **The column policy comes from the grant**, not the object. A grant with a predicate but no
  `COLUMNS` still confines the rows (spec 024); a grant that assigns columns injects them.

### Settings

- `acl_max_ingest_rows` (default `0` = unlimited): the row cap enforced while draining, for a
  deployment that wants a ceiling. Separate from `MAX_PARAM_ROWS`, which bounds bound-parameter rows
  and stays small — ingest is where large data is expected.

### SqlInfo

`FLIGHT_SQL_SERVER_BULK_INGESTION` flips to `true` (spec 047 left the seam with a comment naming this
spec). A driver reads it to decide whether to offer `adbc_ingest`.

## Enforcement & security

- **Fail-closed by default.** The write happens only when every refusal above is passed; anything
  unexpected throws. A refusal mid-stream rolls the transaction back, so a retry cannot double-load.
- **`arrow_scan` is closed to principals** and open only to this server-composed statement, through a
  boolean that no client-authored statement can set. This *removes* surface (the pre-049 reachability
  of `arrow_scan`) rather than adding it.
- **The client authors no SQL.** The insert text is the server's; the field names come from the
  client's Arrow schema and are quoted identifiers in a column list duckdb checks by width and name —
  a stream wider or narrower than the target's writable set is duckdb's own error, not a shifted row.
- **The golden rule holds.** The rewriter adds no parameter here or anywhere; the composed
  statement's `$1..$3` are the door's own, bound to its own pointers in a statement that carries no
  client SQL and therefore no client parameters to renumber. The policy's injected values are baked
  constants, exactly as everywhere else.
- **The caps and the predicate are the write's real gate**, reached through the ordinary INSERT path;
  the transport carries the data, the policy decides the rows.

## Testing

`test/sql/acl_statement_gate.test` (or a focused `acl_arrow_scan_denied.test`): a principal calling
`arrow_scan(…)` / `arrow_scan_dumb(…)` is refused by the gate — the hole this closes, pinned without
a server.

`test/cpp/test_acl_flight_ingest.cpp` (standalone, spec 002 style): the refusals that need no live
stream — `transaction_id` present, `temporary = true`, `if_not_exist = CREATE`, `if_exists = REPLACE`
each answer their named status; a plain append composes the expected insert text (asserted through a
seam, not by side effect).

`test/e2e/flight/` — the live round trip, the acl_quack_ingest analogue over Flight (milestone 2
adds: temporary-ingest a batch, `MERGE INTO` the target from it as text, read back the merged rows;
and a second session neither sees nor resolves the first session's staging name):
- an ADBC `adbc_ingest` of N rows into a writable virtual target **lands**, and the principal reads
  back its own slice (`adbc.sh`, the real driver);
- rows carrying a tenant the grant's predicate forbids are refused where the value is written, and
  nothing of them is stored;
- under a grant that assigns the tenant, the same forbidden rows are accepted and stored with the
  claim's tenant — the client's value replaced, not trusted;
- a stream naming a column the target's writable set lacks is a width/name error, not a shifted row.

The e2e client already hand-encodes DoPut for `@update:` (spec 048); ingest adds an `@ingest:`
verb encoding `CommandStatementIngest` with a small Arrow table, so the pins run under `ACL_QUACK=1`
in CI alongside the existing door tests.

## Alternatives considered

- **Materialize the stream into `Value` rows and executemany**, reusing `ParamRowsFrom` verbatim.
  Simple, and wrong for ingest: it holds the whole load in RAM as a row vector and pays per-value
  boxing for data that never needed to be SQL parameters. `arrow_scan` streams straight into the
  insert's scan.
- **Leave `arrow_scan` allowed and skip the exemption.** Then the composed ingest just works and no
  denylist entry is needed — but the pre-049 reachability of `arrow_scan` stays open, and a feature
  that *depends* on a function being reachable is the wrong moment to leave it reachable to everyone.
- **Merge/upsert through the backend `options` map** (`options["mode"] = "merge"` keyed on the
  spec-048 declared key). The protocol's designers rejected merge in the RPC itself and left the
  options map as the extension seam, so this is *possible* — but a real MERGE needs its matching
  condition and its WHEN branches, and flat string options cannot carry that semantics without
  inventing a private mini-language — and the *actions* (`WHEN MATCHED THEN UPDATE/DELETE/INSERT`)
  are SQL themselves, not just the condition. Decided against: the upsert flow is `temporary = true`
  staging (milestone 2), then a text `MERGE INTO … USING <stage>` with full SQL semantics under the
  `merge` capability.
- **A registry keyed by an ingest id**, like quack's stream registry, so the exemption binds to a
  value rather than a boolean. More faithful to spec 042, but there is no client-named id here — the
  server composes the pointers — so the id would be ceremony around a boolean.
- **Support `temporary` now** by ingesting into a real temp table. That is the session-temp-table
  feature (design/013 §7) with its own resolution and lifetime rules; folding it in here would ship
  half of it. Refuse until it lands, then flip.

## Follow-ups

- **Spec 050 — `create`/`drop` capabilities, and ingest into a declared home.** For a target under a
  *live schema alias* the refusals above dissolve: the alias' `phys_path` is the declared physical
  home, the live listing registers nothing, and the schema's caps already govern visibility — so
  nothing is guessed and nobody self-grants. What is missing is only the right: two new **explicit**
  capabilities, `create` and `drop` (granted on the schema/catalog, never part of the unstated-caps
  default — spec 012's widening rule), and then `if_not_exist = CREATE` composes
  `CREATE TABLE <phys> AS SELECT … FROM arrow_scan(…)`, `if_exists = REPLACE` composes duckdb's
  atomic `CREATE OR REPLACE TABLE … AS …` under `create ∧ drop`, and the plain `CREATE TABLE` /
  `DROP TABLE` statements open through the statement gate under the same caps. One rule travels
  with it: **a confined writer cannot replace or drop** — a grant carrying a predicate, a column
  list or injections writes a slice, and replace/drop destroys every other slice while the CTAS
  shape bypasses the spec-024 insert machinery; refused by construction. A source that cannot push
  the DDL (a scanner without OR REPLACE) surfaces its own error. Until 050 lands, this spec's
  refusals name what is missing (`create` capability / a live-alias home), not a bare "no".
- Full `CREATE TEMP TABLE` statement support under the `temp` capability (design/013 §7) stays a
  later feature; milestone 2's staging covers the ingest-shaped need without it. A per-session quota
  on staged tables/bytes is worth adding when usage shows the shape.
- Ordered/unordered ingest and the parallel insert plan (spec 042's open item) apply here too — no
  test pins the parallel plan specifically yet.
- Transactions: `transaction_id` on ingest waits for the cluster-era transaction work with every
  other write path.
