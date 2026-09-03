# duckdb-acl

Role/token-scoped access control for DuckDB, implemented as a **`parser_override`** that rewrites the
query AST **before bind**. A trusted gateway prepends an `ACL` prefix to every query; the extension
verifies the principal, resolves virtual names to physical objects, applies row-level security and
column masking, gates functions, and hands real `SQLStatement`s back to the normal
bind → optimize → execute path — so both `SELECT` and DML work naturally.

> **Status: pre-release.** The first release follows duckdb 2.0; until then the extension tracks
> **duckdb `main`** (it depends on parser/AST APIs — the `Identifier` type, multi-level `QualifiedName`,
> `MergeQueryNode`, unified DML query nodes — not yet in a stable release). One spec per feature lives
> under [specs/](specs/); [specs/001](specs/001-parser-override-ast-rewrite/spec.md) is the core model.

## How it works

Policy lives in a **policy catalog** — a schema the extension manages in any ATTACHed database — and is
written in management SQL. A statement reaches the engine one of two ways:

- **through a gateway**, which prefixes every statement with the principal it verified:

  ```
  ACL ROLE  "<role>"   <sql>            -- the gateway resolved the role
  ACL TOKEN '<jwt>'    <sql>            -- the extension verifies the JWT offline (issuers, JWKS)
  ACL SESSION '<h>'    <sql>            -- a door's client: token exchanged for a session once
  ```

- **through a door**, for a client that connects for itself: the built-in **Arrow Flight SQL** server
  (`acl_flight_serve`, any ADBC/JDBC driver) or the embedded **quack** server (`acl_quack_serve`). A door
  turns the client's JWT into a session and prefixes every statement after that.

Either way the override rewrites the statement before bind: virtual names resolve to physical objects,
row filters and column masks are applied, functions are gated, and ordinary `SQLStatement`s go on to
bind → optimize → execute.

```sql
LOAD acl;                                    -- enables the override in STRICT mode on load
ATTACH ':memory:' AS store;                  -- any ATTACHed database can hold the policy catalog
SELECT acl_use_db('store', 'acl', true);     -- create/open the managed schema `acl` in it
SET GLOBAL acl_allow_anonymous_admin = true; -- bootstrap: bare ACL ADMIN is allowed for now

ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders;          -- physical target
ACL ADMIN CREATE ROLE analyst CLAIMS (tenant = 'acme');               -- a default claim
ACL ADMIN GRANT CATALOG c TO ROLE analyst MAIN;
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst WITH (select)
    RLS (tenant = acl_claim('tenant'));                               -- row-level security

ACL ROLE "analyst" SELECT id, amount FROM orders;   -- rewritten: ... WHERE tenant = 'acme'

SET GLOBAL acl_allow_anonymous_admin = false;       -- before any door opens
SELECT acl_flight_serve('grpc+tls://0.0.0.0:31337', 'cert.pem', 'key.pem');
```

The memory-mode helpers (`acl_grant_table`, `acl_define_token`, …) are a dev/test substrate: without a
policy catalog the extension cannot serve a client, list metadata or read a JWKS.

## Resolution forms

Per object the resolver picks one of two replacement forms:

| Form | What happens | Writable? |
| --- | --- | --- |
| **RENAME** | virtual name → physical name in place (full path `a.b.c` → `pdb.psch.pobj`); stays a real table | yes (INSERT/UPDATE/DELETE/MERGE) |
| **SUBQUERY** | wrap a `SELECT`: allowed columns, masks, computed columns, RLS constants, or a view/vfunc's SQL | no (read-only) |

Virtual **table functions** and **scalar functions** resolve the same way: a RENAME-alias of a
physical/system function, or a template macro whose call arguments are substituted via `acl_arg(n)` and
whose claims are baked via `acl_claim('<name>')`. Everything else routes through a resolver seam that
denies only data-reading / rights-bypass functions (`read_csv`, `postgres_query`, `getvariable`, …) and
passes the rest.

## Administration

Policy is written in management SQL — `ACL ADMIN CREATE VIRTUAL CATALOG | TABLE | VIEW | SCHEMA |
REFERENCE …`, `CREATE ROLE | ISSUER …`, `GRANT CATALOG | TABLE | SCHEMA … TO ROLE …`, `ALTER … `, `DROP …`
— or through the equivalent `acl_*` functions (`acl_add_relation`, `acl_grant_catalog`,
`acl_define_issuer`, …). Administration is itself a capability (spec 009): `ACL ADMIN` is the
gateway's anonymous form and needs `acl_allow_anonymous_admin`; a principal administers with a
granted `manage` scope (`ACL TOKEN '…' ACL <management statement>`). The legacy memory-mode wrappers
(`acl_define_token`, `acl_grant_table`, …) remain for tests and, with a catalog, write into the
implicit virtual catalog `default`.

## The policy schema

The catalog-backed policy store keeps its own schema — `relations`, `role_catalogs`, `grant_columns`
and the rest — in whatever database you point `acl_use_db(...)` at. `acl_use_db('<db>', 'acl', true)`
creates it for you; the third argument turns that off, for a database where you would rather apply
the schema yourself.

It is written down once, in [`schema/policy_schema.sql`](schema/policy_schema.sql), and everything
else is rendered from it by `make schema`:

| file | what it is |
| --- | --- |
| `schema/acl_schema.sql` | the schema as it stands, ready to run — then `acl_use_db('<db>', 'acl', false)` |
| `src/include/acl_schema_sql.hpp` | what the extension runs when it initialises a catalog |

There are no migrations yet — duckdb-acl has not been released, so every catalog is created at the
current version. [`schema/migrations/README.md`](schema/migrations/README.md) is the contract the
first one will follow.

Because both come from one file, a hand-applied schema and the extension's own cannot drift
apart; `make schema-check` fails if they have, and applies the file to an empty database to confirm
the extension is content with what it finds.

Only the duckdb dialect is kept. The SQL is plain, so translating it to another engine is a job for a
translator rather than for a renderer we would have to keep correct — two things a target may need:
a key column is indexed, so SQL Server needs it bounded (`NVARCHAR(255)`, not `NVARCHAR(MAX)`, which
cannot carry an index — see [specs/033](specs/033-policy-catalog-on-sql-server/spec.md)), and
`IF NOT EXISTS` on `CREATE TABLE` / `ADD COLUMN` is not universal.

## Build

```sh
git submodule update --init --recursive
make                # builds duckdb + the extension (release)
make test           # runs test/sql/acl.test (and the C++ tests on Linux/macOS)
make test-cpp       # standalone C++ invariant tests only (test/cpp/)

make schema            # re-render the policy schema after editing schema/policy_schema.sql
make schema-check      # fail if the rendered files are stale, or if the schema no longer applies

# integration against real databases (docker; see specs/005)
cp .env.example .env
make vcpkg-setup
make docker-up
ACL_INTEGRATION=1 make    # also builds postgres_scanner + ducklake
make test-integration
```

The loadable extension lands at `build/release/extension/acl/acl.duckdb_extension`; the test binary at
`build/release/test/unittest`.

## Testing the whole flow

`test/harness/` has a runnable end-to-end demo (`demo.sql`) that attaches a physical database, registers
policy, and runs `ACL ROLE`/`ACL TOKEN` queries showing RLS, masking, virtual functions and DML. See
`test/harness/README.md`.

## The gateway

Deployment invariant: **only the gateway connects to DuckDB.** The gateway authenticates the caller,
resolves role/claims (online token introspection lives there), prefixes the query, and forwards it. A
reference gateway (Arrow Flight SQL server embedding DuckDB) is planned separately.

## License

MIT — see [LICENSE](LICENSE).
