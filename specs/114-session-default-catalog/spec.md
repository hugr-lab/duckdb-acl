# Spec 114: the session's default catalog

- **Status**: draft
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
   its ambiguity rule, `information_schema` / `SHOW TABLES` with no catalog. `USE` of the role's MAIN
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

Not in this spec: JDBC `setCatalog` / ADBC's catalog option (Flight session options) -
a client sends `USE` instead.

## Enforcement & security

A default changes only how a short name is read, never what is granted: it is checked against the
principal's grants where it is set and again at every resolution (a grant revoked since makes the short
name refuse, as a written one would). Never on a shared connection.

## Testing

- `test/sql/acl_session_catalog.test`: `USE` on an `ACL SESSION` principal - short names in the second
  catalog, back to MAIN, `USE vcat.schema` - a bare name read and created in the schema, `main.x`
  still reached, `USE vcat` resetting it, `USE SCHEMA s` in the current catalog; a catalog or schema not held refused, refused on a
  per-statement prefix, the ambiguity rule against the session's catalog, the resolver cache not shared
  across catalogs; `current_database()`.
- Flight e2e: ADBC sends `USE`, a short name reads the second catalog.
- quack: `USE` through `quack_query_by_name`.

## Alternatives considered

- **A per-role default catalog in the policy** (`MAIN` already is one): a client could not choose per
  session, and JDBC / ADBC's standard calls would still be refused.
- **Flight session options / `SET acl_session_catalog`**: more surfaces for the same thing; `USE` is
  what every SQL client already sends.
- **Accept `USE` as a no-op**: a client would believe it switched and read the wrong catalog.
