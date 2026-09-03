# duckdb-acl documentation

Role/token-scoped access control for DuckDB: a trusted door verifies an OIDC token, resolves virtual
names, applies row-level security and column masking, and serves real clients over Arrow Flight SQL
and quack. The development guide is [CLAUDE.md](../CLAUDE.md); per-feature specs live in
[specs/](../specs/); this folder is the operator- and user-facing documentation.

- [security.md](security.md) - the security model: what is enforced and how, capabilities and
  scopes, accepted risks, the live-alias decision, the error contract, a hardening checklist.
- [management-sql.md](management-sql.md) - the management SQL reference (`ACL ADMIN ...`) and the
  equivalent `acl_*` functions: catalogs, tables, views, schemas, functions, references, roles,
  issuers, grants, ALTER/DROP, batches and authorization.
- [policy-catalog.md](policy-catalog.md) - where policy lives: choosing the catalog database, the
  tables, schema versions and migrations, staleness, the function-driver source, introspection.
- [authentication.md](authentication.md) - the token model: prefix forms, issuers and keys, role
  mapping, how a token is judged, sessions and token binding, how clients get a token.
- [serving.md](serving.md) - serving clients directly: the Flight SQL and quack doors, sessions and
  the ops surface, graceful shutdown, client-local settings, hardening, troubleshooting.
- [deployment.md](deployment.md) - one node, TLS, behind a proxy; where the fleet story lives.
- clients/ - how each client connects: [DBeaver / JDBC](clients/dbeaver.md),
  [ADBC (python)](clients/adbc.md), [duckdb + quack](clients/quack.md),
  [Power BI / Fabric](clients/powerbi-fabric.md).

Status notes are honest: a section marked *planned* names the spec or design that will deliver it.
