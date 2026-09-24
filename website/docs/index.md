---
slug: /
---

# duckdb-acl

Role- and token-scoped access control for DuckDB. A principal - a role a gateway resolved, a verified
OIDC token, or a session a door opened - sees **virtual** catalogs, never the physical databases
behind them. Each statement is rewritten before DuckDB binds it:

- virtual names resolve to physical objects;
- row-level security is applied to reads and writes;
- columns are narrowed and masked;
- every function call is gated;
- the result is ordinary SQL, which DuckDB then plans and runs.

Real clients connect directly through two doors: the built-in **Arrow Flight SQL** server (ADBC,
JDBC/DBeaver, Power BI) and the embedded **quack** server (another DuckDB).

> **Status: pre-release.** The first release follows DuckDB 2.0.

## Where to start

- [Getting started](getting-started.md): from an empty DuckDB to a principal reading a row-filtered
  table, then a client over a door.
- [Concepts](concepts.md): how a statement reaches the rewrite, virtual catalogs, grants and
  capabilities, the function gate, sessions.

## Reference

- [Management SQL](management-sql.md): every `ACL ADMIN …` statement and its `acl_*` equivalent,
  covering catalogs, tables, views, schemas, functions, references, roles, issuers, grants, function
  categories, resource groups and secrets.
- [Policy catalog](policy-catalog.md): where policy lives, the tables, schema versions and
  migrations, staleness, and the function-driver source.
- [Authentication](authentication.md): the prefix forms, issuers and keys, role mapping, how a token
  is judged, sessions, and how clients get a token.
- [Serving clients](serving.md): the Flight SQL and quack doors, sessions and the operator's
  surface, capacity, drain, and troubleshooting.
- Clients: [DuckDB + quack](clients/quack.md), [DBeaver / JDBC](clients/dbeaver.md),
  [ADBC (Python)](clients/adbc.md), [Power BI / Fabric](clients/powerbi-fabric.md).
- [Security model](security.md): what is enforced and how, accepted risks, the error contract, and a
  hardening checklist.
- [Observability](observability.md): the audit, the metrics, and the execution profile.
- [Deployment](deployment.md): one node, TLS, behind a proxy.
- [Development](development.md): building, testing, and the specs.

A section marked *planned* names the spec that will deliver it.
