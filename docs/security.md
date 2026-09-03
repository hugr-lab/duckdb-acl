# Security model

What the extension enforces, how, what it deliberately does not, and what a client may rely on in an
error. Every statement here is taken from a spec or from the source; where a behaviour was verified
by running it, the section says so. Specs are cited as `spec NNN` and live in [`specs/`](../specs/).

## 1. The model in one page

**The trust boundary is the connection.** The extension enforces nothing on a statement nobody
prefixed: "an unprefixed query runs natively and unrestricted in every mode, which is why only the
gateway may connect" (spec 017). The deployment invariant from `CLAUDE.md` is therefore the whole
perimeter: **only the gateway connects to DuckDB** - or, when clients are served directly, only the
doors (section 5), which prefix every statement themselves.

**The prefix is the principal.** A statement arrives as `ACL ROLE "<role>" <sql>`,
`ACL TOKEN '<jwt>' <sql>`, `ACL SESSION '<handle>' <sql>`, `ACL INGEST '<handle>' <insert>` (a door's
own composition, never a client's) or the anonymous `ACL ADMIN <sql>`. "Exactly one prefix is
stripped; the remainder is parsed natively; role/claims apply to the whole `;` batch" (spec 001).
`ROLE` trusts the gateway; `TOKEN` verifies offline; `SESSION` and `INGEST` resolve a handle a door
already exchanged a token for. A second `ACL …` inside the text is text: "Exactly one prefix is
stripped (spec 001) and the inner parse runs with the override disabled, so `ACL ROLE "r" ACL NATIVE
ACL ADMIN CREATE VIRTUAL CATALOG x` reaches duckdb's own parser as `ACL ADMIN CREATE …` and fails
there - no re-entry, no mode laundering" (spec 009).

**The rewrite happens before bind.** The extension is a `parser_override`: it rewrites the parsed
AST and "returns real `SQLStatement`s to the normal execution path" (spec 001). Enforcement is
structural, not a filter: "a denied column is absent from the safe subquery, so the binder rejects
it; RLS claim values are baked as constants (pool-safe, no session state)". Two replacement forms
exist - **RENAME** (virtual name to physical name in place, writable) and **SUBQUERY** (a wrapped
SELECT carrying projection, masks, computed columns, RLS or view SQL, read-only) - and the resolver
picks per object.

**Fail-closed defaults.**

- "An unknown/denied name is refused (never left for the binder to hit the real catalog). A direct
  physical name is not a mapped virtual name ⇒ denied" (spec 001).
- The markers `acl_claim('<name>')` and `acl_arg(n)` "are not real functions ⇒ a missed marker fails
  closed at bind" (spec 001).
- The statement gate, the query-node gate and the table-reference gate each end in `default: Deny`
  (`src/acl_rewriter.cpp`): an AST form the rewriter does not enumerate is refused, which is what
  makes a co-loaded extension's opaque `ExtensionStatement` refused under the prefix (spec 067).
- Denials are **thrown, never returned**: "Refusals are security output; they do not get a channel
  a neighbour can mute" (spec 017). The extension sets `allow_parser_override_extension='STRICT'`
  on load unless a value was set explicitly before loading; at `DEFAULT` "no `ACL …` statement
  parses" - loud, not silent - and `acl_use_db` / `acl_use_functions` refuse to configure a policy
  that cannot be enforced (spec 017).

**The golden rule.** "The rewriter adds **no query parameters** - a user's `$1`/`?` is the only
parameter and binds normally" (spec 001). User-supplied values "are inserted as AST nodes (no text
injection)"; the door-composed ingest binds its own `$1..$3` in a statement that "carries no client
SQL and therefore no client parameters to renumber" (spec 049).

**State is per instance.** The `PolicyStore` - policy, sessions, drain flag - is reached through
`AclParserInfo` / `AclScalarInfo`, "no process globals, so two instances in one process never
share sessions" (spec 040).

## 2. What is enforced, per surface

### Reads

- `select` gates **every read position**: "Every read position routes through `RewriteTableRef`
  (subqueries, `EXISTS`/`IN`, CTE bodies, `INSERT … SELECT` sources, DML `FROM`/`USING`), so one gate
  covers them all" (spec 003). A write-only object "cannot be read anywhere in a statement -
  including from inside the statement that legitimately writes it".
- A virtual **function call is a read too**: a virtual table function or scalar needs `select`
  before its template is expanded, "so a denied call never reaches bind - its template is not even
  parsed" (spec 012).
- A grant only narrows: "a grant may narrow, never widen" (spec 011/012). An object grant's column
  list may hide or mask a column the object exposes and nothing else - "naming, computing and
  ordering belong to the virtual catalog" (spec 037). A catalog-wide list intersects by bare name
  and **refuses** where a mask cannot be applied: "an unapplied *mask* is an error, never a skipped
  protection" (spec 038). Two roles masking one column differently are refused (spec 011/026).
- A CTE name never resolves as a catalog object (spec 001).

### Writes

- The per-verb capability (`insert`/`update`/`delete`/`merge`) gates every DML target, and a
  target must be RENAME-form: "Declaring `COLUMNS` on the *object* makes it a projection, and a
  projection is read-only by construction" (spec 042).
- **A grant's predicate confines what is written** (spec 024): it is AND-ed into the `WHERE` and
  checked per row where the value is written - `CASE WHEN <predicate over the new row> THEN <value>
  ELSE error('… cannot be written') END`. "A violating row fails the whole statement rather than
  being dropped from it". An insert under a predicate "must name its columns, and must supply every
  column the predicate reads - or be given one by an injection, which counts". `ON CONFLICT … DO
  UPDATE` and both `MERGE` branches carry the same policy. Injected columns override what the
  writer supplied.
- With a second relation in scope (`UPDATE … FROM`, `DELETE … USING`, `MERGE`) the predicate is
  qualified with the target's alias so "a same-named source column cannot capture it"; a `MERGE`
  carries it on the `ON` clause and on every `WHEN NOT MATCHED BY SOURCE` branch (spec 020). A
  predicate containing a subquery that was never checked where it was written is refused on those
  four paths (spec 027) - "Fail closed on the unknown".

### DDL

- The statement gate admits `CREATE` and `DROP` and the rewriter decides: "only tables and views
  can be created through the ACL"; a table lands in a granted physical home under the explicit
  `create` capability, `DROP` needs `drop`, and `CREATE OR REPLACE` is priced at `create`+`drop`
  because "REPLACE is a drop" (specs 016/051). A plain `CREATE` refuses an existing name (spec 051).
- The policy record a principal's DDL writes "can only add a record for the object just created, and
  its shape is fixed (`alias` form, the schema's origin) - a principal cannot choose a form, a
  projection or an RLS clause" (spec 016). `create` "is a data capability, not a manage scope, and
  no amount of DDL produces one".
- A principal's `CREATE VIEW` is "resolved once, with its author's rights, and reading it is decided
  by the grant on the view" (spec 018).
- `CREATE TEMP TABLE` needs the explicit `temp` capability; a temp name is resolved
  "virtual-first" and a miss "keeps today's `Deny("no access")`"; a temp over a granted virtual name
  is refused (spec 050).

### Functions (`PolicyStore::FunctionAllowed`, `src/acl_policy.cpp`)

The gate is a **denylist**, evaluated in this order:

1. every function whose name starts with `acl_` is denied to a principal - "otherwise one statement
   (`SELECT acl_grant_admin('me','passthrough')`) defeats the whole model" - and stays available in
   the native context; a granted virtual function named `acl_*` still resolves before the seam;
2. `arrow_scan` / `arrow_scan_dumb` are hard-denied "AHEAD of the catalog gate, so an
   `acl_allow_function` row can never re-open a pointer-dereference primitive" (spec 049); the one
   exemption is the door's own `ACL INGEST` statement;
3. the policy catalog's allow/deny rows (`acl_allow_function` / `acl_deny_function`), then
4. `DefaultDeniedFunctions()`: file and blob readers (`read_csv`, `read_parquet`, `read_json*`,
   `read_text`, `read_blob`, `glob`, …), spatial readers, external-source scanners and SQL
   passthroughs (`postgres_query`, `postgres_scan`, `mysql_*`, `mssql_*`, `sqlite_*`, `iceberg_*`,
   `delta_scan`, `query`, `query_table`), session and secret state (`getvariable`, `which_secret`,
   `current_setting`, `current_query`), every `duckdb_*` / `pragma_*` / `show_*` metadata function
   that "enumerate[s] every attached database", quack's own surface (`quack_query`, `quack_cancel`,
   `quack_serve`, `scan_data_from_quack_client`, …), `acl_quack_scan_data` and `whoami`.

The consequence is stated in spec 041 and holds today: "loading an extension extends the function
surface, and this gate is a denylist - so its failure mode is the thing nobody named."

### Metadata

- The catalog surfaces are **replaced by the principal's own listing**, in duckdb's own shapes
  (specs 010/035): `information_schema.tables|columns|schemata`, `duckdb_tables`, `duckdb_views`,
  `duckdb_columns`, `duckdb_schemas`, `duckdb_databases` (function and view forms alike). "The
  physical world does not appear in any of them" (spec 031). `test/sql/acl_metadata_leak.test` pins
  that an ungranted table "is in none of them, under any name" and that `duckdb_databases()` does
  not list the physical database.
- Surfaces with no filtered form stay denied by the function gate: `duckdb_secrets()`,
  `duckdb_constraints()`, `pragma_table_info(...)` as a function, `duckdb_settings()`,
  `duckdb_functions()` (same test; spec 052).
- `DESCRIBE <name>` becomes `DESCRIBE (SELECT * FROM <name>)`, so it describes the rewritten
  relation (spec 025); `SHOW TABLES`, `SHOW DATABASES`, `SHOW SCHEMAS`, `SHOW ALL TABLES` answer
  from the listing; `SHOW VARIABLES` is refused; `PRAGMA table_info` / `PRAGMA show_tables` are
  answered through `DESCRIBE` and every other PRAGMA "stays denied, because a PRAGMA is otherwise a
  setting" (spec 031).
- The session-identity functions answer as the principal: `current_database()`,
  `current_catalog()`, `current_schema()`, `current_schemas()` return the MAIN virtual catalog
  (`test/sql/acl_metadata_leak.test`, spec 010 part 3).
- A grant's projection is probed where it is written and stored in `grant_columns`, "so
  `information_schema.columns` describes what the role reads" (spec 026). `duckdb_tables().sql` is
  never NULL and `is_insertable_into` "follows the grant, not the physical row" (spec 065,
  `test/sql/acl_listing_truth.test`).
- References (spec 022) are "a hint an agent reads, never enforced and granting nothing; visible
  only when both ends and every column it names are".

### Statements (`AclRewriter::RewriteStatement`, `src/acl_rewriter.cpp`)

| statement type | under a principal |
| --- | --- |
| `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE INTO` | rewritten (sections above) |
| `EXPLAIN [ANALYZE]` | needs the explicit `explain` capability on the MAIN grant, then the inner statement is rewritten (spec 052) |
| `CREATE`, `DROP` | tables and views only, under `create`/`drop`/`temp` (above) |
| `PRAGMA` | `table_info`, `show_tables` answered; the rest denied by name (spec 031) |
| `SET` / `RESET` | `TimeZone`, `Calendar` only, session scope, constant value, only on an `ACL SESSION` connection (spec 068) |
| `BEGIN` / `COMMIT` / `ROLLBACK` | pass through: "they are session control, not access" |
| anything else | `acl_rewrite: statement type <T> is not permitted under ACL` |

`test/sql/acl_statement_gate.test` pins `CONNECT` and `DISCONNECT` refused ("CONNECT hands every
following statement's text to another executor, stepping around the rewriter"); spec 067 pins
`statement type EXTENSION is not permitted under ACL` for a co-loaded extension's peeled syntax.
Below the statement gate, an unknown query-node type or table-reference form is refused the same way.

### Settings

A principal sets nothing that changes "what a name resolves to (`search_path`), what is read
(`file_search_path`, `enable_external_access`), or what a statement costs (`threads`,
`memory_limit`)" (spec 068). `SET GLOBAL` is refused; `SET VARIABLE` is refused; a listed setting
without a session of the client's own is refused, so "a prefix-per-statement deployment never
carries state between principals". The extension's own settings are `SetScope::GLOBAL`, read
through the `DatabaseInstance`, so a session-scoped `SET` cannot silently change nothing (spec 009,
spec 040 addendum for `acl_jwt_clock_skew`).

### Doors

`RefuseUnlessServable` (`src/acl_door_common.cpp`) refuses to open either door when: no policy
source is configured; `acl_allow_anonymous_admin` is on ("a served client could administer the ACL
with a bare `ACL ADMIN`"); the parser override is not `STRICT` ("a served statement that failed to
parse as ACL would fall through to plain SQL"); or there is no TLS certificate and the address is
not loopback ("without a TLS certificate the door serves in the clear, so it binds only localhost").
Only the last is lifted by a certificate or by quack's explicit `mode := 'plain'`; "the three above
stand regardless". The quack door additionally demands a server token ("a default-configured quack
accepts whatever a caller sends, and this is the outer fence around that") and refuses `plain` mode
combined with a certificate. Both doors require cert **and** key together.

### Administration (spec 009)

- Administering the ACL is a granted capability: `{"manage": true}` on a catalog grant (per
  catalog), or a global `manage` / `passthrough` row in `acl.admins`. "A `manage` scope never
  leaves the virtual catalog (`ACL NATIVE` is `passthrough` only) and never hands out scopes."
- The client writes the marker after the principal: `ACL <mgmt>` needs `manage` or `passthrough`;
  `ACL NATIVE <sql>` - "plain SQL **outside** the virtual catalog - god mode" - needs
  `passthrough`. "Choosing a marker grants nothing by itself."
- "A catalog-scoped `manage` edits its catalogs' content but may not run `GRANT|REVOKE CATALOG` or
  `ALTER GRANT`" - handing out access is privilege administration; `acl_grant_admin` /
  `acl_revoke_admin` require `passthrough`: "no self-escalation".
- A management batch "is authorized **statement by statement at parse time**, so a refusal anywhere
  in it executes nothing"; execution itself is not atomic.
- The anonymous `ACL ADMIN` hatch "is off by default the moment a real policy source exists"
  (`acl_allow_anonymous_admin`), and a door refuses to open while it is on.
- What `manage` really is: "may expose, through C, anything the DuckDB instance can reach - the
  grammar's `phys` targets are not themselves restricted … manage scopes belong to trusted
  operators".

## 3. Capabilities and scopes

| capability | where it is granted | in the unstated default? | gates |
| --- | --- | --- | --- |
| `select` | catalog, schema, object grant | yes | every read of a relation; every virtual function call (specs 003/012) |
| `insert`, `update`, `delete`, `merge` | catalog, schema, object grant | yes | the DML verb on a RENAME-form target; predicate-checked per row (spec 024) |
| `manage` | catalog grant (`{"manage": true}`) | **no** | `ACL <mgmt>` over that catalog; never `GRANT CATALOG` / `ALTER GRANT` / admin scopes (spec 009) |
| `create`, `drop` | schema (or catalog) grant | **no** | `CREATE TABLE|VIEW` into the granted physical home; `DROP`; `CREATE OR REPLACE` = both (specs 016/051) |
| `temp` | MAIN catalog grant | **no** | `CREATE TEMP TABLE` and temp-name resolution on a session connection (spec 050) |
| `explain` | MAIN catalog grant | **no** | `EXPLAIN [ANALYZE]` - "a plan names the physical objects a query resolves to" (spec 052) |
| admin scope `manage` (global) | `acl.admins` via `acl_grant_admin` | - | the management grammar over every catalog plus catalog-less statements |
| admin scope `passthrough` | `acl.admins` via `acl_grant_admin` | - | everything, including `ACL NATIVE`; the only scope that grants scopes |

The rules behind the table (spec 012): a grant "written without `CAPS` - or a driver row with
NULL/empty caps - means `select, insert, update, delete, merge`, never `manage`; an explicit `'{}'`
means none"; "an *object* grant that states nothing inherits the catalog grant's caps, so a
refinement never widens by omission"; the capabilities outside the default "are explicit-only and
never inherited". A schema grant "carries **capabilities only** - no RLS, no column list" (spec 015).
Capabilities and predicates union across a principal's roles; column lists union in the object's
order (specs 026/038).

## 4. Identity

The token model - who verifies, who acquires, the admin's flow menu, session token binding - is in
[authentication.md](authentication.md). What matters for enforcement:

- `ACL ROLE` "trusts the gateway (role + optional default claims)"; `ACL TOKEN` "verifies offline →
  role + claims" (spec 001) - RS256/ES256/HS256, issuer, audience, `exp`/`nbf`, keys pasted or read
  from a document (specs 007/023). "An unverified token never reaches the scope question" (spec 009).
- A session "carries exactly the prefix's principal, both ways" (spec 040 addendum, 2026-09-03):
  `SessionOpen` now merges role-default claims exactly as `ACL TOKEN` does, so the same token answers
  the same slice through a door and through a gateway. `acl_jwt_clock_skew` is GLOBAL, like every
  sibling setting.
- `acl_session_token_binding='connect'` (default) judges `exp` at establishment only; `'every_use'`
  re-judges it on every statement (spec 059). "An expired token can never *open* a session under
  either setting" (authentication.md).
- The Flight password handshake runs the IdP's password grant as the issuer's `client_id`; "the
  IdP's refusal is the gate"; it is refused on a cleartext door and while draining; `acl_issuers()`
  never lists the client secret (specs 064/066).

## 5. Doors and sessions

**Handles, tickets and cookies are bearer credentials**, and they come from one minter.
`MintRandomHex` (`src/acl_policy.cpp`) reads `std::random_device` - the OS CSPRNG on glibc, libc++
and MSVC - and checks the device is not deterministic (MinGW before GCC 9.2 "returned a fixed
sequence"): "Refusing to mint beats minting that" (spec 040). Since the 2026-09-03 addendum to spec
045 the session handle, the Flight ticket id and the Flight session cookie are all minted there. A
handle is "never derived from the token, never logged by us, revocable by `acl_session_close`, and
useless outside this instance".

**Who holds what.**

- Gateway contract (spec 040): `acl_session_open`/`acl_session_sql`/`acl_session_close` mint,
  compose and end; all three are `acl_*` and therefore denied to a principal, so "a client can
  neither mint a session, nor compose a prefix, nor close somebody else's".
- quack (spec 041): the connection id is "a bearer credential in quack's model; our handle is
  separate, minted by us, and only ever appears in SQL we compose". The callbacks "run on a fresh
  transient connection of quack's own making".
- Flight (spec 050): the session cookie "only selects a session, and only one of the **same
  principal**" - the match is the principal fingerprint including the token's subject; "a cookie
  presented with a different principal's token closes the old session and opens a fresh one"; the
  token is verified **before** the idle clock is touched; "Our handle never leaves the server". A
  ticket is a single-use reservation redeemable only by the fingerprint that made it, and "a
  mismatch answers exactly like a handle that never existed: no oracle" (spec 047).

**A session is a connection** (spec 050): statements execute on the session's own held `Connection`
under a per-session lock; temp tables are "per-connection by construction, so no principal can
reach another session's temp through any surface"; duckdb reclaims everything when the session ends.
A cookie-less call gets a per-call session closed on the way out.

**Bounds** (spec 044): a session dies at idle (`acl_session_idle_timeout`, default 900 s) or - under
`every_use` - at `exp`; `acl_max_sessions` (default 1000) is a cap at which "a new session is
**refused**, never an old one evicted"; `SessionOpen` sweeps by itself. Arrow's own session store is
closed alongside ours so it "cannot grow without bound".

**Drain** (spec 066): `acl_drain()` sets one flag on the store and `SessionOpen` refuses "before
verifying anything"; it "never ends a session"; established sessions keep working; `ACL TOKEN` /
`ACL ROLE` statements keep working; the three drain functions are denied to a principal; quack's
discovery document answers 503 `draining`. Ending a straggler is `acl_session_kill`, an operator's act.

**The unprefixed drain fence** (spec 042; `src/acl_parser_override.cpp`). quack generates its bulk
`INSERT … SELECT * FROM <scan>(…)` **unprefixed** on the client's connection. While a door of this
instance is open (`store.DoorOpen()`), any unprefixed statement that *calls* `acl_quack_scan_data` or
`scan_data_from_quack_client` is either rewritten under the principal recovered from the stream id
(`connection_id:uuid` → session → principal) or refused: "The refusal is the default and the rewrite
is the exception". The recovered principal carries `ingest_stream` set to that exact id, so the
denylisted scan passes "for that principal and nothing else". With no door open the fence is off -
a stock quack's own ingest "is its own business".

**The Flight ingest** (spec 049): the door composes `INSERT … SELECT … FROM arrow_scan($1,$2,$3)`
under `ACL INGEST '<handle>'`, a prefix "composed only by the door's own C++"; it admits "exactly one
INSERT or CREATE TABLE statement" (the CREATE form is spec 050/051's staging and create/replace). A
client cannot author it: "every door wraps client text as `ACL SESSION '<handle>' <text>`, so an
embedded `ACL INGEST …` is mid-statement garbage". The load is one statement, so a refusal on row N
stores nothing, and the row count is cross-checked against the rows the stream delivered.

**Instance identity** (spec 045 addendum): a door holds a `weak_ptr<DatabaseInstance>` to its
opener; a stop from another instance is refused (`belongs to another database instance`).

## 6. Accepted risks and known limits

Each item below is written down in a spec as accepted, pending or open. None is a data leak; two
are name leaks bounded to an already-granted principal.

- **Binder errors can name physical columns for an unknowable shape (spec 065, accepted).** For "a
  bare alias, every table function", a misconfigured grant or a drifted source mapping "still
  surfaces **duckdb's** binder error, which names physical columns … What leaks is *names, never
  data*: RLS and masks are not bypassed, and only a principal already holding a grant on that object
  can provoke it - an admin-misconfiguration surface, not an outsider's." Declared shapes refuse
  cleanly (`acl_rewrite: object "orders" exposes no readable columns`, pinned in
  `test/sql/acl_listing_truth.test`), and "declaring the shape upgrades any given object to clean
  refusals". A mask whose column is gone surfaces duckdb's `Column "ssn" in REPLACE list not found`
  (spec 038). The named compensating control, `acl_check_catalog` (spec 039), **does not exist
  yet** (`specs/BACKLOG.md`).
- **A write-path binder error cites the physical leaf table name (spec 052, accepted).** An
  `INSERT`/`UPDATE` naming a nonexistent column gets duckdb's `Table "orders_physical" does not have
  column …`: the principal "already holds a write capability on *this exact object*, learns only its
  unqualified leaf name (never the catalog/schema/database), and only by deliberately naming a
  column that does not exist".
- **A plan names physical objects - by grant (spec 052).** `EXPLAIN` under the `explain`
  capability shows `phys.schema.table`; "that a principal who may run a query also learns where it
  lands is acceptable *behavior*, but it belongs to a role that was granted it".
- **Upsert against an invisible row (spec 020).** Under RLS a `MERGE` may insert beside a row the
  principal cannot see; where a unique constraint exists "the failure does disclose that *some* row
  with that key exists outside the principal's slice … a deployment that cares should not grant
  `merge` on a table whose key space is shared across tenants".
- **Concurrency under load is not yet proven (spec 043, draft).** Isolation is by construction -
  the override receives no `ClientContext`, "which is *why* identity rides in the statement text";
  each session executes under its own lock on its own connection - and the e2e harness runs three
  legs (postgres, mssql, ducklake) with two clients streaming 20 000 rows each, asserting "slices
  stay separate, no row is stored outside the slice that wrote it, and concurrent ingests add up".
  Not yet written: a reader during another client's drain, the cross-source join under load, session
  lifecycle across clients. The backlog lists this as a release blocker.
- **An ingest is atomic per statement, not per stream (spec 042).** A session that expires
  mid-stream "ends the drain with an error and a partially written table". The fence keys on two
  scan names; "if quack ever drains a stream by another name, an unprefixed write runs natively
  again".
- **Foreign syntax is refused under the prefix (spec 067).** A co-loaded extension's peeled
  statement is an opaque `ExtensionStatement`: "an AST we cannot enumerate is an AST we cannot
  confine". It works only under `ACL NATIVE` (passthrough). An **unprefixed** foreign query "runs
  without the ACL - the same property every unprefixed query has" (spec 017).
- **The function gate is a denylist** (spec 041): a newly loaded extension's functions are allowed
  until named. Quack's fourteen functions and `arrow_scan` were added when found.
- **The listing narrows while a declared object is dead.** Verified today (section 7): after the
  source drops a mapped column, `SELECT *` fails with the binder error above while
  `information_schema.columns` lists the remaining columns. `specs/BACKLOG.md` (pre-release): "The
  listing marks a broken object instead of narrowing it". Likewise "an object whose mask cannot be
  applied is unreadable but still listed" (spec 038).
- **`manage` is trusted-operator territory** (spec 009): its physical targets are unrestricted; "a
  physical allowlist per scope is possible future work".
- **Management and native SQL through the doors** are the session's scope, exactly (spec 009
  addendum, 2026-09-03; `test_acl_session.cpp`): no scope is refused both, `manage` administers but
  is refused `ACL NATIVE` and cannot grant itself `passthrough`, and `passthrough` runs native SQL
  including the node's control surface - that is the operator path over a door, by decision.
- **No audit trail yet** (blocker 3, decided in the release): no event per engine decision exists
  today.
- **Memory mode** (no policy catalog) is the dev stub: the anonymous hatch is unconditionally open
  there (spec 009), and it cannot serve, list or read a JWKS.
- **`RETURNING` on a refused row** names the grant, not the row - deliberately, "a row identifier
  in the message … would leak the row to the principal" (spec 024).
- **Sessions are per node.** There is no shared session backend; a cluster front routes by cookie.

## 7. The live-alias decision: what happens when the source grows

This is policy an operator must read. It was verified on today's build
(`build/release/duckdb`, 2026-09-03) by adding and dropping physical columns and tables under every
object form, and it agrees with specs 014/026/029/037/038/065.

**A "live" alias is live and total.** A virtual table that is a plain alias (`CREATE VIRTUAL TABLE
c.orders AS phys.main.orders`, no `COLUMNS`) read through a **whole-table grant** (no `COLUMNS` on
any grant in the chain) shows a column added to the physical source later - `ssn_backup` appeared in
`SELECT *` and in `information_schema.columns` for the role the moment it was added, with nobody
granting it. That is what live means, and spec 014 states it at the schema level: an alias schema
"resolves through the prefix, live: a table added physically is visible at once, and nothing can be
excluded". Verified: a table created in the source after `CREATE VIRTUAL SCHEMA c.raw AS phys.main`
was readable as `raw.newtab` and listed at once.

**A mask is by name.** `ssn = NULL` protects the column named `ssn` and knows nothing about an
`ssn_backup` added later. Whether the new column is *visible* depends only on whether a column list
is in force somewhere in the chain:

| object form | grant | column added to the source | column dropped from the source |
| --- | --- | --- | --- |
| plain alias | whole-table (no `COLUMNS`) | **appears, ungranted** | the object adapts (the rest is readable) |
| plain alias | `COLUMNS (id, tenant, ssn = NULL)` | invisible - not listed | a bare name intersects away (spec 038); a masked name that vanished **refuses** with duckdb's `Column "ssn" in REPLACE list not found` |
| plain alias | `COLUMNS (ssn = NULL)` (mask only) | invisible - the list is the masked column alone | refuses, as above |
| declared object (`COLUMNS (id = pk, tenant = internal_tenant, ssn = ssn_raw)`) | any | invisible until declared | **the object refuses, it does not narrow** - with duckdb's `Referenced column "ssn_raw" not found in FROM clause! Candidate bindings: "ssn_backup", "internal_tenant"` (spec 065 probe A, the accepted name leak); `information_schema.columns` meanwhile lists `id, tenant` |
| alias schema (`AS`) | whole-table | a **whole new table** appears and is listed | the table is gone |
| expansion schema (`FROM`) | whole-table | invisible (`no access to object "cur.newtab"`) until `ALTER VIRTUAL SCHEMA c.cur REFRESH`, which reported `1` and made it readable | `REFRESH PRUNE` removes the record (spec 014) |

Three consequences, stated as the decision:

1. **A whole-table grant on a live alias is a grant on the source's future.** A catalog-wide mask
   such as `ssn = NULL` does not cover an `ssn_backup` added later; with a whole-table grant that
   column is readable in the clear. A schema alias likewise exposes every table the source grows.
2. **For sensitive objects, declare the shape.** Give the object an explicit `COLUMNS (…)` list
   (or grant with a `COLUMNS` list): a new physical column is then invisible until it is declared,
   and a dropped one makes the object refuse rather than quietly narrow. Note what "refuse" means
   here: the refusal is duckdb's binder error and names physical columns (the spec 065 accepted
   risk) - it is fail-closed on data, not name-tight. The name-tight refusal (`acl_rewrite: object
   "orders" exposes no readable columns`) is the empty-intersection case on a declared object.
   Repair is the administrator's, by rewriting the object's list (`ALTER VIRTUAL TABLE … SET
   COLUMNS`): a refresh (`acl_refresh_schema` / `ANALYZE VIRTUAL CATALOG`, spec 010) re-probes
   verdicts and derived schemas but does not heal a declared list - healing it automatically would
   drop a mask silently, which spec 038 refuses. The check-and-repair procedure is spec 039 (not
   yet written).
3. **Expansions record objects; aliases do not.** `CREATE VIRTUAL SCHEMA … FROM` is "a snapshot plus
   edits"; new source tables need `REFRESH`, an excluded object stays excluded, and this is the only
   way to exclude a single table (spec 014: "nothing about this is dynamic-with-exceptions").

## 8. The error contract

Every refusal the extension raises carries a prefix that names its subsystem, then a message that
names **virtual facts only**: "every message a principal can provoke names only what the principal's
own catalog shows - virtual names, virtual columns, the acl prefix" (spec 065). The exceptions are
the accepted-risk cases in section 6, where duckdb's own binder error - not ours - surfaces physical
names to an already-granted principal.

Prefixes in use (`grep -rhoE '"acl[a-z_ ]*:' src/ | sort | uniq -c`, 2026-09-03), and what each
marks:

| prefix | raised by | what it marks |
| --- | --- | --- |
| `acl_rewrite:` | the prefix scanner (`ParserException`), principal resolution (`… token rejected: …`, `… role verification failed`, `… session unknown|expired|idle`), every `Deny()` of the rewriter (`BinderException`), the per-row write check (`InvalidInputException` via `error()`: `the row does not satisfy the grant on "<name>", so it cannot be written`), template errors | **a principal's statement was refused** - the class a client sees most |
| `acl admin:` | the management grammar and its authorization in `acl_parser_override.cpp`, the admin functions, the catalog writers | a management statement or admin function was malformed or not authorized (`a bare ACL ADMIN is disabled - …`) |
| `acl catalog:` | `acl_policy_catalog.cpp` | the policy-catalog backend: malformed caps/claim JSON, a failed catalog read/write/transaction, the read-only function driver |
| `acl:` | the drain fence (`a streamed insert carries no principal, so it would be written outside the policy (…)`), door runtime refusals returned as `arrow::Status` (`node is draining - not accepting new sessions`, transaction and ticket errors, the password handshake), the multi-relation predicate check, join-expression checks, internal errors (`this build's std::random_device is deterministic, …`) | the door or the store refused something that is not one statement's rewrite; **also** the description text of every `acl_*` setting, which the grep counts |
| `acl_flight_serve:`, `acl_quack_serve:`, `acl_flight_stop:`, `acl_quack_stop:` | the serve/stop functions (`RefuseUnlessServable` substitutes the function name) | a door could not be opened or closed: preconditions, TLS arguments, an occupied uri, `belongs to another database instance` |
| `acl_define_issuer:`, `acl_use_functions:` | that function | its own argument validation |
| `acl oidc secret:` | `src/oidc/acl_oidc_secret.cpp` | the **client-side** OIDC secret provider (spec 061), not the node |
| `acl_quack_scan_data:` | the embedded door's drain | internal (`no active stream`) |

Two counted matches are not prefixes: `acl embedded door:` is the description of the embedded
server's settings, and `acl_references takes at most one argument: …` / `acl_keys takes …` are
`Deny()` bodies that reach a client as `acl_rewrite: acl_references takes …`.

What a client may rely on:

- the prefix is stable enough to match on: a message beginning `acl_rewrite:` is a policy refusal
  of the statement, one beginning `acl admin:` is a management refusal, one beginning `acl:` came
  from a door or the store;
- a refusal names the virtual object (`no access to object "cur.newtab"`, `select on "audit_log" is
  not allowed`, `statement type CONNECT is not permitted under ACL`) and never data;
- through the Flight door a refusal arrives as the gRPC status the door chose (`Unavailable` for
  draining, `Invalid`, `KeyError`, …) with the same text; through quack, an authentication or
  authorization refusal is quack's own "Authentication failed" / "Authorization failed" (spec 041).

The rule (release plan 4.4): **the prefix is the contract; the exception class says which kind of
thing went wrong; the wording after the prefix is not promised.** A client matches on the prefix and,
if it needs more, on a keyword (`no access`, `not allowed`, `read-only`, `draining`) - never on the
whole sentence. duckdb prints the class in front of every message:

| class | printed as | when |
| --- | --- | --- |
| `BinderException` | `Binder Error:` | a refusal or a policy/configuration problem: every `acl_rewrite:` and `acl admin:` refusal, `acl catalog:`, a door precondition (`acl_flight_serve: …`), an occupied uri |
| `InvalidInputException` | `Invalid Input Error:` | the shape of an argument or a token: a NULL where a value is required, malformed JSON, the per-row write check |
| `IOException` | `IO Error:` | the environment, not the policy: a certificate or key that could not be read or parsed, a listen address that could not be bound (`acl_quack_serve: failed to bind …`, `acl_flight_serve: …`) |
| `ParserException` | `Parser Error:` | the prefix itself (`acl_rewrite: …`) or the statement text after it does not parse |

A token that does not verify is refused as `acl_rewrite: token rejected: <reason>` on the prefix
path (`ACL TOKEN '…'`); a door never sees that text - `acl_session_open` answers NULL and
`acl_quack_authenticate` false, and `acl_session_reason` says why a session is gone.

## 9. Hardening checklist

Before a node serves anyone:

- [ ] Nothing but the gateway or the doors can open a connection to the DuckDB instance. Every
      unprefixed statement is unrestricted; this is the perimeter.
- [ ] `allow_parser_override_extension` is `STRICT` (set on load; verify nobody set it before
      loading, and nobody runs `SET GLOBAL … = 'DEFAULT'`).
- [ ] A policy catalog is configured (`acl_use_db`); memory mode is the dev stub.
- [ ] `acl_allow_anonymous_admin` is **off** once the first `passthrough` admin exists; the doors
      refuse to open while it is on.
- [ ] Admin scopes are minimal: catalog-scoped `manage` for operators of one catalog, `passthrough`
      for the platform only - it is "the actual god mode" and the only scope that runs `ACL NATIVE`.
- [ ] Sensitive objects declare `COLUMNS (…)`; no whole-table grant sits on a live alias whose
      source may grow (section 7). Schema aliases are used only where "everything, forever" is
      intended; otherwise expand with `FROM` and `REFRESH` deliberately.
- [ ] Explicit-only capabilities are granted by name and reviewed: `create`, `drop`, `temp`,
      `explain`, `manage`. `EXPLAIN` shows physical names to whoever holds `explain`.
- [ ] `merge` is not granted on tables whose key space is shared across tenants (spec 020).
- [ ] Every loaded extension's functions are reviewed against the denylist - the gate is a
      denylist, and a new extension widens the surface until named (`acl_deny_function`).
- [ ] Grants' predicates and projections carry a `true` verdict (`acl_relations()`,
      `acl_object_grants()` show `rls_checked`); run `acl_refresh_schema` with every source attached
      (spec 027).
- [ ] Doors leave the machine only over TLS (`acl_flight_serve(uri, cert, key)`;
      `acl_quack_serve(uri, token, cert, key)`), or `mode := 'plain'` sits behind a TLS-terminating
      proxy on purpose. The quack server token is set explicitly.
- [ ] Session bounds fit the deployment: `acl_max_sessions`, `acl_session_idle_timeout` (never `0`
      under `connect` binding), `acl_session_token_binding` (`every_use` where revocation latency
      matters), `acl_max_ingest_rows` where a ceiling is wanted.
- [ ] Issuers: audiences are never `'*'` by accident; `acl_jwks_max_stale` is `0` if a failed JWKS
      read must be fatal at once; `KEYS FROM` locations are trusted (an allowlist is a backlog item).
- [ ] Stopping a node follows spec 066: `acl_drain()` → watch the count → `acl_session_kill` for
      stragglers → `acl_flight_stop` / `acl_quack_stop` → close duckdb. Stop the Flight door before
      closing the instance.
- [ ] The accepted risks of section 6 are known to whoever owns the policy: physical column names
      in a binder error reach only an already-granted principal, and only on shapes the catalog
      does not know.

## Unverified

Listed so nobody takes them for facts:

- The "drift matrix" that spec 065 rests on is in the local, gitignored `design/BACKLOG.md`
  ("probed 2026-08-21"); section 7 re-ran it on today's build and reports what that run showed. Not
  probed: DML under drift, a catalog-level alias (which does not exist).
- Spec 043's harness assertions are taken from the spec text; the run itself was not repeated here.
- The gRPC status classes per Flight refusal are read from `src/flight/acl_flight_door.cpp`; not
  every status was enumerated.
- Spec 028 (DML in a CTE) was not read for this document.
