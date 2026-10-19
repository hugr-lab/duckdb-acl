# Spec 136: a listing says which source it could not read

- **Status**: implemented (accepted by the owner 2026-10-19: «По спекам ок» - the mark names the source, as
  written; the build corrected the problem statement, see "What the build found")
- **Date**: 2026-10-19
- **Author**: Claude (with the owner)

## Summary

A listing reads only the physical facts of the sources it answers about (spec 119). A source that fails is left out
so the rest of the listing still answers. Until now its objects went with it, and nothing said why: a client saw
fewer tables, an operator saw nothing at all.

The owner, 2026-10-18 (design/082, A2, before the release): the listing says it. Each object over a source that could
not be read stays listed and carries a mark in its comment, the way a broken declared list does (spec 039). The node
also emits an audit event and counts it.

## Problem

`acl_physical_tables` / `acl_physical_columns` (`src/acl_platform_sources.cpp`) caught a source's failure and dropped
its rows: `// a source that cannot answer is left out`.

- A Postgres that is down, a SQL Server login that expired, a DuckLake whose catalog is unreachable: the listing
  joins each virtual object to its physical row with an inner join, so an object whose source failed **vanished**
  from `information_schema.tables`, `duckdb_tables()`, `SHOW TABLES` and the Flight `GetTables` RPC (which reads
  `information_schema.tables`).
- An alias schema over such a source (`CREATE VIRTUAL SCHEMA c.s AS pg.public`) stayed listed, empty: its tables are
  the source's, read live.
- A client could not tell "this table is gone" from "its source is down". DBeaver and an agent's MCP listing lose
  the table without a word.
- The operator's surfaces (`acl_check_catalog`, the audit, `/metrics`) were silent: the failure was swallowed on the
  query path.
- `platform.attached` (spec 118.3) left a failing source out of the admin's tree in the same way.

## Design

### The reader reports what it could not read

The physical reader keeps its rule: a failing source never fails the listing. It now also says which sources failed.
A third table function from the same reader, `acl_physical_unread(keys)`, answers one row per source schema whose
read threw: `(database_name, schema_name, error_class)`.

- `error_class` is the exception's type (`Exception::ExceptionTypeToString`: `IO`, `Connection`, `Permission`,
  `Catalog`, `Binder`, ...). It is never the message: a source's error can carry a host, a user, a path (the rule of
  spec 069's ingest errors). Measured: a Postgres that refuses the login answers `IO`; a DuckLake whose metadata
  database went away answers `Binder`.
- A key whose database is not attached at all answers `not attached`. An object over a detached source is the same
  case to a reader. It is **marked, never counted nor recorded**: absence is not a failure - a source attached on
  another group's nodes only (spec 096), or a detach the operator made (`acl_check_catalog` says `source_missing`).
  (A hidden database - another catalog's internals - is skipped as before, never marked.)
- What is no source's failure goes on: an interrupt (a cancelled statement), and what duckdb ends the instance on
  (`InvalidatesDatabase`: FATAL and the like, and INTERNAL). A message that only looks like serialized error data
  classifies as `Invalid`, never throws again inside the handler.
- **One read per failing source per statement.** The readers share a cache (`PhysicalReadCache`, a
  `ClientContextState` cleared at each query's begin and end): for each `<db>.<schema>` its failure, the keys read
  whole, and per database whether it answered.
  - A schema that failed is not read again in the statement by any reader; the others answer from the cache.
  - A database whose first read failed before it answered anything (a server down, a login refused, a detach) fails
    every schema alike: its other schemas are not tried. One listing over a down Postgres with k schemas pays one
    timeout, not k.
  - `acl_physical_unread` only probes what no sibling read yet (the catalog lookup and the scan that makes a catalog
    load its tables) and builds no row. The admin's `acl_platform_attached[_columns]` read through the same cache.
  - DuckDB initializes a plan's sources in parallel and in an order of its own, so the cache's lock is held across a
    reader's whole init and no order is assumed; a reader checks the interrupt after the lock (a sibling's cancelled
    read cached nothing).
  - This stops one listing from paying a down source's timeout once per inlined subquery (`itables`, `icolumns`,
    `physcols`, `unread`): measured by the counter, one listing over a failing database with two schemas counts 1.
  - A source that answers is still read by each reader that needs its rows (its catalog is the scanner's cache).
  - The granularity is the schema: a failure met by any reader (the columns path's too - a scanner that loads a
    table's columns lazily) marks every object of that schema in the statement.
- Never on the function gate's open list: like its two siblings it is the listing's (an `acl_*` name, the never set),
  substituted by the rewriter, and refused when a principal names it.

### The listing marks the objects over it

`MetadataListingSql` adds an `unread` CTE over `acl_physical_unread(<the same keys>)` and joins it like `physcols`
(spec 039's broken mark). Only the surfaces that show the mark ask for it: the tables surfaces
(`information_schema.tables`, `SHOW TABLES`, `duckdb_tables()`, `duckdb_views()`) over every key they read, and
`duckdb_schemas()` over the alias schemas' keys only. Every other surface (databases, schemata, columns, keys) gets
an empty `unread` and reads no source it did not read before (spec 119: only the sources it answers about). The
comment of an object whose physical catalog and schema failed becomes:

```
acl: source <database> could not be read (<class>); <the object's own comment>
```

The database is named only to a principal that may read the object (one of its roles' caps chain admits `select`):
its failed read would say as much. A principal that only sees the object - a grant without `select`, which spec 012
still lists - reads `acl: source could not be read (<class>)`; spec 035 keeps physical names out of its listings. The
same rule holds for an alias schema's mark (the schema's caps).

(The draft's "- its columns are not listed" is gone: an object whose policy stores its columns - a declared list, a
grant's projection - still lists them, so the clause would be false for it.)

- **Surfaces:**
  - `information_schema.tables` (`TABLE_COMMENT`), `SHOW TABLES`: the object is listed again - the tables surface's
    join to the physical row is a LEFT JOIN kept for an unread object - with `table_type` `BASE TABLE` (the physical
    row that said otherwise is what could not be read) and the mark.
  - `duckdb_tables()`: keeps spec 065's rule - an object with no column to describe is not listed there (a NULL
    `sql` broke a quack client's whole catalog). An object whose columns the policy stores is listed, with the mark.
  - `duckdb_schemas()` (`comment`): an alias schema over a source that could not be read - its tables are unknown,
    the schema says why: `acl: source <database> could not be read (<class>)`, then its own comment.
  - `platform.attached` for the admin: the failed source stays a node of the tree, `platform.attached.<alias>`, its
    `duckdb_schemas()` comment the same mark.
- **Precedence:** the broken mark of spec 039 needs the source's columns, so the two never meet on one object. The
  unread mark wins: nothing about the declared list is known.
- **Columns surfaces** list nothing physical for such an object, as before; what the policy stores (a declared list
  of a subquery form, a grant's projection) is listed as before. The tables surface is where the reason is said.
- **The Flight catalog RPCs** read `information_schema.tables`, so `GetTables` lists the object again - with no
  comment (Flight SQL's schema has no remarks column) and, with `include_schema`, the columns the listing has (none
  for an alias form). A table whose source is down is listed, not lost.
- **The narrowing** (spec 119) is untouched: the failed keys are those of the sources the narrowed listing read (an
  alias schema narrowed by a table name is still read - its tables are not known before it is).

### The operator sees it

- **An audit event `policy` / `source_unreadable`**: `objects = [{name: <database>, capability: source}]`,
  `reason_code` `source_error`, `reason` the mark's text. No principal rides on it.
  - It is recorded once per source and class a minute (`PolicyStore::AuditSourceUnreadable`, a bounded map), and
    `acl_audit_denials_per_second` applies on top as to any refusal.
  - It is counted at every failed read: `acl.listing.sources_unreadable{class}`, added where the failure is met (like
    `acl.jwt.verifications`). The attribute values come from a bounded set, the exception types.
  - A source is a database the node attached, so its name is the operator's and no principal's data.
- **`acl_check_catalog`** already probes every relation's source off the query path (spec 039 `source_missing`).
  Nothing is added there: this spec is about the moment a listing meets the failure.

## Enforcement & security

- **No error text reaches a principal or the audit, only the exception's type.** A source's message can name a
  host, a login or a path (the integration test checks that the login, `host`, `FATAL` are nowhere in the comment).
- **The mark is said only for an object the principal already sees:** the join runs inside the principal's listing,
  after its policy CTEs; an object is listed again only when it is one the principal's grants show.
  - A principal learns that a source of its own object failed, and of which class. That is less than a read of the
    object would tell it: a read fails with the source's error itself.
  - The source's database name in the mark is the physical key the object resolves to, named only to a principal
    that may read the object - the same thing its failed read would disclose. One that may not reads the class alone
    (review 136: a `select`-less grant saw the name, which nothing else showed it).
  - The owner accepted the mark as written, naming the source (2026-10-19).
- **The audit event** has its own rate bucket (`door::listing`), so a burst of `policy` / `keys` failures in the same
  second never drops the one record a minute a failing source gets; the floor runs on a steady clock (a wall clock
  set back would silence it).
- **No new parameters** (the golden rule). `acl_physical_unread` takes the same constant key list its siblings take.
- **Fail-safe direction:** a failure still never fails the listing, which is spec 119's rule. Only the silence goes.

## What the build found

- The draft said an object over a failed source was listed with no columns. It was not listed at all (the inner
  join); listing it again with the mark is what the accepted design needed, and it changes what `GetTables` returns
  (the object is back, without columns for an alias form).
- Review 136 (three passes: the reader and its cache, security, the listing SQL) found: the `unread` read on every
  surface (SHOW DATABASES, schemata, columns paid a down source's timeout), the name shown to a `select`-less grant,
  a failure retried per schema of one down database, `platform.attached` outside the cache, `not attached` counted
  as a failure (permanent noise on a node of another group), the classifier able to throw inside its handler,
  FATAL / INTERNAL swallowed, the floor's shared rate bucket and wall clock - all fixed above, each with a test where
  one can say it. Accepted: a physical VIEW behind an unread object is listed as `BASE TABLE` while its source is
  down.
- In the sqllogictest runner a DuckLake scan needs `require parquet`: without it DuckLake's
  `GetScanFunctionById` calls a scan function with no bind (a SIGSEGV - DuckLake's, reproduced with no ACL listing
  at all; its deserialize path checks for it, this one does not).

## Testing

- **sqllogictest** (`test/sql/acl_listing_unread_source.test`):
  - A DuckDB file attached as a source, a virtual table over it (with a comment), an alias schema over another of its
    schemas, a readable second source, a principal granted the catalog.
  - DETACH the source: `information_schema.tables` lists the table with the mark (`not attached`, then its comment),
    `information_schema.columns` lists none of its columns, `duckdb_tables()` leaves it out (spec 065), the alias
    schema's `duckdb_schemas()` comment carries the mark, the readable source is unchanged.
  - A role whose grant has no `select` reads the mark without the database's name (object and alias schema).
  - `not attached` is marked and never counted.
  - `acl_physical_unread` named by a principal is refused; the operator's call answers the two schemas.
  - A DuckLake whose metadata database is detached, with objects over two of its schemas: the mark says `Binder` on
    both; one listing counts 1 (one read for the failing database); `duckdb_databases()`, `SHOW DATABASES`,
    `information_schema.schemata`, `SHOW SCHEMAS` count none; the admin's `platform.attached.lake` node carries the
    mark; the ring holds one event for it after several listings, and none for the source not attached.
- **Integration** (`test/sql/integration/acl_listing_unread_postgres.test`, with the scanner): a Postgres source
  attached under its own login; the login is taken away (`NOLOGIN`), its backends ended, the scanner's cache cleared.
  The mark says `IO`; the scanner's text (the login, the host, `FATAL`) is nowhere in the result; no column is
  listed.

## Alternatives considered

- **Failing the whole listing.** spec 119 chose the opposite on purpose: one source down must not blind a client to
  every other.
- **A warning channel.** DuckDB results have none, and Flight SQL has none for a statement's rows. A comment is what
  every client already shows.
- **The error's message in the mark.** It can carry a host, a login or a path. The class is what a reader acts on,
  and the operator's own surfaces read the source directly.
- **A column of its own** (`acl_source_status`) on the tables surfaces. It would widen the shapes that duckdb's own
  views have, which the listings keep (spec 025).
- **Caching the readers' rows too.** A source that answers is cheap to read again from its scanner's catalog; what
  costs is a failure's timeout, and only that is cached.

## Follow-ups

- A relation stored with a two-part physical name (`CREATE VIRTUAL TABLE c.x AS db.t`) is never listed by the tables
  surface (`len(parts) = 3`), healthy source or not, and `physcols` keys it as schema `t` - found by review 136,
  older than it.

- The console (hugr-platform 003) can show the unread sources from the counter and the events.
- The Flight catalog RPCs could carry the mark if Flight SQL's `GetTables` grows a remarks column.
