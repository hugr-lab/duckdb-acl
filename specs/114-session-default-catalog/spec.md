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

1. **What it is.** A session (a door's `ACL SESSION`, spec 068's `Principal::session_connection`) may
   name a default catalog, and optionally a schema in it. Short names then resolve there instead of in
   the role's MAIN catalog: the catalog plays MAIN's part in every rule that names MAIN - reads, writes,
   spec 113's DDL reading, the ambiguity rule, `information_schema` / `SHOW TABLES` with no catalog.
   A default schema is tried first for a bare name, then the catalog's own `main`.
2. **Who may set it.** Only on a session of the client's own (a gateway's per-statement prefix shares
   the connection - the setting would be the next principal's). Only a catalog (and schema) the
   principal holds a grant on; anything else is refused with what it may name. It grants nothing: the
   same name resolves to the same object under the same grants as when written in full.
3. **How it is set:**
   - `USE <vcat>[.<schema>]`, and `SET schema = '…'` (what USE is), under a principal;
   - Flight `SetSessionOptions` `catalog` / `schema` (the names ADBC and Arrow's JDBC send) and
     `GetSessionOptions` answering them;
   - for quack, where `USE` is the client's own: `SET acl_session_catalog = '<vcat>[.<schema>]'` through
     `quack_query_by_name`, as spec 107's lineage parent is set;
   - `RESET` / an empty value returns to the role's MAIN catalog.
4. **Where it is kept.** On the session's record (like spec 107's lineage context), so every door's
   composition carries it; the principal resolved for a statement carries it into the resolver, and
   every cache keyed by the principal's roles is keyed by it too.
5. **What answers it:** `current_database()` / `current_schema()` under a principal answer the virtual
   catalog / schema (today the node's own, which names nothing a principal can use).

## Enforcement & security

A default changes only how a short name is read, never what is granted: it is checked against the
principal's grants where it is set and again at every resolution (a grant revoked since makes the short
name refuse, as a written one would). Never on a shared connection.

## Testing

- `test/sql/acl_session_catalog.test`: USE / SET schema on an `ACL SESSION` principal - short names in
  the second catalog, a default schema, RESET, a catalog not held refused, refused on a per-statement
  prefix, the ambiguity rule against the session's catalog, the resolver cache not shared across
  defaults; `current_database()`.
- Flight e2e: ADBC sets the catalog option, a short name reads the second catalog; JDBC
  `setCatalog`.
- quack: `SET acl_session_catalog` through `quack_query_by_name`.

## Alternatives considered

- **A per-role default catalog in the policy** (`MAIN` already is one): a client could not choose per
  session, and JDBC / ADBC's standard calls would still be refused.
- **Accept `USE` as a no-op**: a client would believe it switched and read the wrong catalog.
