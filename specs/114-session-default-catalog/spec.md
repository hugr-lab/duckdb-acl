# Spec 114: the session's default catalog

- **Status**: implemented (accepted by the owner 2026-10-09)
- **Date**: 2026-10-09
- **Follows**: spec 113 (DDL names; its "Next" section), spec 068 (client-local settings), spec 050 (a
  Flight session is a connection)

## Problem

A short name (`orders`, `dbt_home.m`) resolves in the role's MAIN catalog - the one catalog grant marked
`MAIN`, if the principal's roles have exactly one. A principal with several catalogs reaches the others
only by writing the catalog in front, and a client that sets its catalog the standard way gets a
refusal:

- `USE mart` / `USE mart.out` is duckdb's `SET schema = …`, refused under a principal (only TimeZone /
  Calendar may be set, spec 068);
- JDBC `Connection.setCatalog/setSchema` and ADBC's current catalog / schema options arrive at the
  Flight door as session options, refused (`kInvalidName`);
- a quack client's `USE` changes its own local catalog, never the node's.

## Design

The simplest form (owner, 2026-10-09): **the client sends `USE <vcat>;` and that changes its default
catalog; `USE <vcat>.<schema>;` also sets its default schema.**

1. **What it does.** On the principal's session, the named virtual catalog takes the MAIN catalog's
   part: short names (`orders`, `dbt_home.m`) resolve there - reads, writes, spec 113's DDL reading and
   its ambiguity rule, a bare `SHOW TABLES` (and `SHOW TABLES FROM <schema>`). `USE` of the role's MAIN
   catalog goes back.
   - **`USE <vcat>.<schema>`** also makes that schema the default: a bare name (`m`) resolves in it -
     as duckdb's own `USE db.schema` does, nowhere else (an object of the catalog's `main` is then
     `main.orders`) - and a bare `CREATE TABLE m` lands there. A two-part name is read as before.
     `USE <vcat>` alone resets the schema to the catalog's `main`.
   - **`USE SCHEMA <schema>`** sets the default schema in the current default catalog (the session's,
     else MAIN). duckdb's parser does not know this form, so the parser override reads it under a
     principal prefix and compiles it like `USE <vcat>.<schema>`. `USE <x>` alone always names a catalog
     - never a schema - so the two never mean each other.
2. **Who may.** Only on a session of the client's own (a door's `ACL SESSION`, spec 068's
   `Principal::session_connection`): a gateway's per-statement prefix shares its connection, where the
   choice would be the next principal's. Only a catalog the principal holds a grant on; anything else
   is refused, naming the catalogs it holds; a schema the principal holds no grant on is refused the
   same way. It grants nothing - a short name reaches what the name
   written in full reaches, under the same grants.
3. **Through every door alike** - it is a statement: Flight (ADBC, JDBC: `USE sales` as SQL), quack
   (`FROM quack_query_by_name('<alias>', 'USE sales')` - a plain `USE` there is the client's own).
4. **Where it is kept.** On the session's record, so every statement of the session carries it into
   the resolver; caches keyed by the principal's roles are keyed by it too.
5. **`current_database()` / `current_schema()`** under a principal answer the session's virtual catalog and schema (today the node's
   own, which names nothing a principal can use).

Going back: `USE SCHEMA main` returns the default schema to the catalog's root; `USE <vcat>` (no
schema) does that too, and `USE <the role's MAIN catalog>` returns the session to where it began.

A catalog has no default schema of its own (owner, 2026-10-09): its root - the objects stored under a
bare name, called `main` - is the default; a session picks another with `USE SCHEMA`.

Not in this spec: JDBC `setCatalog` / ADBC's catalog option (Flight session options) -
a client sends `USE` instead.

## Enforcement & security

A default changes only how a short name is read, never what is granted: it is checked against the
principal's grants where it is set and again at every resolution (a grant revoked since makes the short
name refuse, as a written one would). Never on a shared connection.

## Testing

- `test/cpp/test_acl_session_use.cpp` (a handle is minted at runtime): `USE` on an `ACL SESSION`
  principal - short names in the second catalog, back to MAIN, `USE vcat.schema` - a bare name read,
  created, inserted into, viewed, renamed and dropped in the schema, `main.x` still reached, `USE vcat`
  resetting it, `USE SCHEMA s` in the current catalog (comments around it too); `SHOW TABLES`; the
  ambiguity rule against the session's catalog; quoted and differently cased names; a USE inside a
  batch; another session's own; `SET GLOBAL|VARIABLE schema` still refused; temps under a USE; lineage
  names under a USE (a batch's too); a revoked catalog; `current_database()`.
- `test/sql/acl_session_use.test`: refusals on a per-statement prefix, `acl_session_use` is no
  principal's.
- Flight e2e: ADBC sends `USE SCHEMA` / `USE`, a bare CREATE lands in the schema and a bare read reads it.
- quack: `USE m` through `quack_query_by_name`, a short name reads `m`, `USE c` goes back.

## Alternatives considered

- **A per-role default catalog in the policy** (`MAIN` already is one): a client could not choose per
  session, and JDBC / ADBC's standard calls would still be refused.
- **Flight session options / `SET acl_session_catalog`**: more surfaces for the same thing; `USE` is
  what every SQL client already sends.
- **Accept `USE` as a no-op**: a client would believe it switched and read the wrong catalog.

## As built

- **Kept on the session record** (`Session::use_catalog` / `use_schema`), set by the follow-up
  `acl_session_use(<ops id>, vcat, schema)` the rewriter composes after its checks - at execution, by
  the session's non-secret ops id (`Principal::session`), never at parse and never by the handle. No
  change to the ext-common `Principal` contract.
- **Applied in the rewriter** (`AclRewriter::Key`): a short name is qualified with the session's
  catalog (and, for a bare name, its schema) before the resolver sees it, so the resolver, its caches
  and spec 113's DDL rules are untouched - a qualified name was already resolved in any catalog the
  principal holds. Metadata surfaces stay as written (`information_schema.*` lists every catalog the
  principal holds, as before; a bare `SHOW TABLES` is the session's schema). `temp.…` stays the
  session's temp catalog. The same qualification serves reads, DML targets (a door's ingest too - it
  runs under the session), CREATE / DROP / RENAME and `CREATE SCHEMA` (a path whose first part is no
  held catalog is the session catalog's). Not qualified: virtual table / scalar function names (they
  still resolve in the role's MAIN catalog) - a follow-up if a client needs it.
- **A USE inside a batch** applies to the statements after it (`USE mart; SELECT … FROM facts`), and
  each statement's lineage job carries the USE it was read under (`AuditTrail::Statement::use_*`): the
  worker qualifies the job's names by `Key`'s rule and binds the statement in a scratch that `USE`s the
  same catalog / schema - the session's USE of the moment it runs is not what the statement ran under.
  `USE SCHEMA s` is read only as a statement on its own (a request of its own); `USE <vcat>[.<s>]` is
  duckdb's grammar and may stand in a batch. Only an automatic or `SESSION` scope is a USE: `SET GLOBAL
  schema` / `SET VARIABLE schema` stay refused as before.
- **Temps** (spec 050): `CREATE TEMP TABLE` is refused when the name is an object of the MAIN catalog or
  a stored object of the session's schema (the anti-shadow rule; a live schema alias claims every name,
  which is no object - the temp is then `temp.main.<x>`, as a door's ingest addresses it). A bare DROP of
  a name the session's schema has no object for is the temp's only where the temp catalog is known (the
  Flight door's context); elsewhere it is the home's, as before. A bare `SHOW TABLES` still lists the
  session's temps.
- **Not transactional**: a USE is the session's, like duckdb's own `USE`; a ROLLBACK does not undo it.
- **A schema needs a schema grant to be USEd** (`role_schemas`, as `CREATE SCHEMA IF NOT EXISTS` reads
  it); a catalog only reachable through schema grants cannot be `USE`d - refused, never widened. The
  ambiguity rule weighs the same held schemas.
- **JDBC**: a client `CREATE VIEW` / `ALTER` / `DROP` prepared through Flight is now announced with an
  empty dataset schema (it runs at GetFlightInfo), so JDBC takes its update path for it.
- **`USE SCHEMA s`** is compiled by the parser override into `SET acl_use_schema = 's'` (duckdb has no
  such grammar); duckdb's `USE x[.y]` is its own `SET schema = '…'`. Both go to `RewriteUse`.
- **Flight**: a client statement that is a command (`SET`/`USE`, `CREATE`, `DROP`, `ALTER`) runs at
  `GetFlightInfo` (`ClientStatementIsCommand` in `AnswersOnlyCount`), whatever the rewrite made of it -
  found by the e2e: `USE` became the record's `SELECT acl_session_use(…)`, a query, left to a DoGet ADBC
  never sends. The same held for a `CREATE VIEW` (`SELECT acl_register_view(…)`) and a view RENAME.
- **Tests**: `test/cpp/test_acl_session_use.cpp` (the positive path - a handle is minted at runtime),
  `test/sql/acl_session_use.test` (refusals on a per-statement prefix, the function is no principal's),
  the Flight e2e (ADBC `USE SCHEMA` / `USE`), the door e2e (quack through `quack_query_by_name`).
