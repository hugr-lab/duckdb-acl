# duckdb-acl documentation

Role/token-scoped access control for DuckDB: a trusted door verifies an OIDC token, resolves virtual
names, applies row-level security and column masking, and serves real clients over Arrow Flight SQL
and quack. The development guide is [CLAUDE.md](../CLAUDE.md); per-feature specs live in
[specs/](../specs/); this folder is the operator- and user-facing documentation.

- [authentication.md](authentication.md) - the token model: who verifies, who acquires, the admin's
  flow menu, session token binding.
- [deployment.md](deployment.md) - one node, TLS, behind a proxy; where the fleet story lives.
- clients/ - how each client connects: [DBeaver / JDBC](clients/dbeaver.md),
  [ADBC (python)](clients/adbc.md), [duckdb + quack](clients/quack.md),
  [Power BI / Fabric](clients/powerbi-fabric.md).

Status notes are honest: a section marked *planned* names the spec or design that will deliver it.
