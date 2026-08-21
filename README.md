# duckdb-acl

Role/token-scoped access control for DuckDB, implemented as a **`parser_override`** that rewrites the
query AST **before bind**. A trusted gateway prepends an `ACL` prefix to every query; the extension
verifies the principal, resolves virtual names to physical objects, applies row-level security and
column masking, gates functions, and hands real `SQLStatement`s back to the normal
bind → optimize → execute path — so both `SELECT` and DML work naturally.

> **Status: proof-of-concept.** The resolvers are in-process stubs (policy registered via SQL helper
> functions). It tracks **duckdb `main`** because it depends on parser/AST APIs (the `Identifier` type,
> multi-level `QualifiedName`, `MergeQueryNode`, unified DML query nodes) that are not yet in a stable
> release. See [specs/001-parser-override-ast-rewrite/spec.md](specs/001-parser-override-ast-rewrite/spec.md).

## How it works

A gateway sends, per request, one of:

```
ACL ROLE  "<role>"   <sql> ; <sql> ; ...
ACL TOKEN '<token>'  <sql> ; <sql> ; ...
ACL ADMIN            <sql>            -- passthrough, no rewrite
```

Enable the override for the session, then run prefixed queries:

```sql
LOAD acl;
SET allow_parser_override_extension = 'fallback';   -- ACL … is rewritten; everything else is native

-- admin setup (in production these are the read-only ACL resolver, not SQL calls)
SELECT acl_grant_table('analyst', 'orders', 'phys.main.orders_physical',
                       'id,amount', 'tenant = acl_claim(''tenant'')', 'select');
SELECT acl_define_token('tok', 'analyst', 'tenant=acme');

ACL TOKEN 'tok' SELECT id, amount FROM orders;   -- (SELECT id, amount FROM phys… WHERE tenant='acme')
```

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

## Admin / setup functions (stubs)

`acl_define_token`, `acl_define_role`, `acl_grant_table`, `acl_grant_view`,
`acl_grant_table_function[,_alias]`, `acl_grant_scalar[,_alias]`, `acl_deny_function`,
`acl_allow_function`. These populate the per-database policy store; a production build replaces them
with the read-only, role-aware ACL resolver behind the same store seam.

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
