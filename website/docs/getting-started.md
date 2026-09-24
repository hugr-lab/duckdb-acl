# Getting started

This page takes a fresh DuckDB from nothing to a principal reading a row-filtered table, first
through a trusted gateway's prefix and then through a door a real client connects to. Each step links
to the page that covers it in full.

> **Status: pre-release.** The first release follows DuckDB 2.0. Until then the extension tracks
> DuckDB's 2.0 release branch (`v2.0-cyanoptera`), so you build it from source (below) against that
> branch.

## 1. Build and load

```sh
git clone --recursive https://github.com/hugr-lab/duckdb-acl
cd duckdb-acl
GEN=ninja make            # duckdb + the extension, release build
build/release/duckdb      # a CLI with acl built in
```

`LOAD acl` (implicit in the CLI above) switches DuckDB's parser override to `STRICT`. From then on
every `ACL …` statement is the extension's. A setting you made before loading is left alone.

## 2. A policy catalog

Policy lives in a schema the extension manages, inside any attached database: a DuckDB file, a
DuckLake, Postgres or SQL Server. See [Policy catalog](policy-catalog.md).

```sql
ATTACH 'policy.duckdb' AS store;
SELECT acl_use_db('store', 'acl', true);       -- create or open the managed schema `acl`

-- the data a principal will see through the ACL
ATTACH 'warehouse.duckdb' AS phys;
CREATE TABLE phys.main.orders(id INT, tenant VARCHAR, amount INT);
INSERT INTO phys.main.orders VALUES (1, 'acme', 100), (2, 'globex', 200);
```

## 3. Write the policy

While there is no administrator yet, the gateway's anonymous form `ACL ADMIN …` writes policy. It
needs a switch that you turn off again before anything serves.

```sql
SET GLOBAL acl_allow_anonymous_admin = true;

ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders;
ACL ADMIN CREATE ROLE analyst CLAIMS (tenant = 'acme');
ACL ADMIN GRANT CATALOG c TO ROLE analyst MAIN;
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst WITH (select)
    RLS (tenant = acl_claim('tenant'));
```

The virtual name `orders` is what a principal writes. The physical `phys.main.orders` is never
visible to them. The RLS predicate is AND-ed into every read, and it also confines writes. See
[Management SQL](management-sql.md) for every statement, and [Concepts](concepts.md) for what they
mean.

## 4. Query as a principal

A trusted gateway puts the principal in front of the statement:

```sql
ACL ROLE "analyst" SELECT id, amount FROM orders;
-- rewritten before bind: ... FROM phys.main.orders WHERE tenant = 'acme'
```

Anything the grant does not cover is refused before it runs. For example, the physical name
`phys.main.orders` is refused, and so is a function outside the role's categories.

## 5. Real tokens

In production the principal comes from a verified OIDC token, not a role name. Register the issuer
once; its keys can come from its JWKS document. See [Authentication](authentication.md).

```sql
ACL ADMIN CREATE ISSUER 'https://login.example.com/realm'
    KEYS FROM 'https://login.example.com/realm/protocol/openid-connect/certs'
    AUDIENCES ('duckdb') ALGS (RS256) ROLE CLAIM 'roles';

ACL TOKEN 'eyJhbGciOi…' SELECT * FROM orders;
```

## 6. Serve clients directly

A client that connects for itself cannot add a prefix, so a **door** does it. The door turns the
client's token into a session and prefixes every statement after that. See
[Serving clients](serving.md).

```sql
SET GLOBAL acl_allow_anonymous_admin = false;   -- a door refuses to open while it is on

-- Arrow Flight SQL: ADBC, JDBC (DBeaver), Power BI
SELECT acl_flight_serve('grpc+tls://0.0.0.0:31337', 'cert.pem', 'key.pem');

-- quack: another DuckDB attaches this one
SELECT acl_quack_serve('quack:0.0.0.0:9494', 'a-server-token', 'cert.pem', 'key.pem');
```

Then connect a client: [DuckDB + quack](clients/quack.md), [DBeaver](clients/dbeaver.md),
[ADBC](clients/adbc.md), or [Power BI / Fabric](clients/powerbi-fabric.md).

## Next

- [Security model](security.md): what is enforced, and the risks the design accepts.
- [Observability](observability.md): the audit, metrics and execution profiles. The
  [acl-otel](https://hugr-lab.github.io/acl-otel/) extension exports them over OpenTelemetry.
- [Deployment](deployment.md): TLS, proxies, and the shape of a fleet.
