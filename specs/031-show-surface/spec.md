# Spec 031: every `SHOW` answers its own question

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

Spec 025 answered `SHOW TABLES` from the principal's own catalog and, without meaning to, answered
every other `SHOW` with it too: `SHOW DATABASES` returned a list of tables. Each form now answers what
it asks, in the shape DuckDB answers it with, and `PRAGMA table_info` — the oldest spelling of "what
columns does this have" — is answered rather than refused.

## Problem

DuckDB's transform folds `SHOW TABLES`, `SHOW DATABASES`, `SHOW SCHEMAS`, `SHOW VARIABLES` and
`SHOW ALL TABLES` into one `ShowRef` of type `SHOW_UNQUALIFIED`, carrying *what* to show in the name
(`"databases"`, `"schemas"`, …, or the marker `__show_tables_expanded`). The rewriter ignored the name
and answered them all with the table listing, in the shape `SHOW TABLES` has:

| asked | DuckDB's shape | answered with |
| --- | --- | --- |
| `SHOW DATABASES` | `(database_name)` | table names |
| `SHOW SCHEMAS` | `(database_name, schema_name, current)` | table names |
| `SHOW ALL TABLES` | `(database, schema, name, column_names, column_types, temporary)` | table names |
| `SHOW VARIABLES` | `(name, value, type)` | table names |

Not a leak — everything returned came from the principal's own catalog — but every answer was wrong,
and a client that asks which databases it has and gets table names will do something wrong with them.

Two smaller ones surfaced with it:

- **A bare `SHOW TABLES` listed the `main` schema of *every* granted catalog.** An unqualified name
  resolves in the MAIN catalog, so the rest are names the client cannot use as written.
- **`PRAGMA table_info('x')` was refused** by the statement gate, along with every other PRAGMA. It is
  what a JDBC/ODBC-shaped client sends before anything else.

## Design

**Dispatch on what was asked.** `ShowTarget` reads the name DuckDB's transform stored (unquoting it),
and each target gets a listing built in its own shape:

- `databases` → the granted catalogs, one column;
- `schemas` → catalog, schema, and a `current` flag that is true for `main` of the catalog the
  principal holds as **MAIN** — which is exactly where an unqualified name resolves;
- `__show_tables_expanded` → the tables of every granted catalog folded together with their columns,
  the same fold DuckDB does over `duckdb_tables` + `duckdb_columns`, built from the `columns` surface
  so a column the object does not project is absent from it;
- `tables` (bare) → the MAIN catalog's `main` schema;
- `tables` with `SHOW TABLES FROM` → unchanged (spec 025).

The three new shapes are listing surfaces rather than SQL assembled in the rewriter, because the
main-catalog test needs the `grants` CTE, which only `MetadataListingSql` has. The
`information_schema` surfaces are untouched.

**`SHOW VARIABLES` answers with nothing, in the right shape.** A principal has no session variables:
`getvariable` is denied and nothing sets one for it. An empty result beats an error for a client that
asks on connect.

**`PRAGMA table_info` goes through `DESCRIBE`, not through the listing.** The rewrite builds
`SELECT … FROM (DESCRIBE (SELECT * FROM <name>))` and rewrites *that*, so the answer comes down the
read path: a name the principal has no access to is refused exactly as `DESCRIBE` refuses it, rather
than answered with no rows — which a client would read as "a table with no columns". The statement is
replaced through the existing `drop_statement` + `follow_ups` seam, so nothing in the entry point
changed.

**Every other PRAGMA stays denied.** A PRAGMA is otherwise a setting, and a principal sets nothing;
only `table_info` and `show_tables` name the catalog.

## Enforcement & security

- **Nothing became visible.** Every new answer is built from the same listings that already governed
  `information_schema`; the physical world does not appear in any of them, and a column an object does
  not project is absent from `SHOW ALL TABLES` as it is from everywhere else.
- **`PRAGMA table_info` is a read and is gated like one** — it goes through `DESCRIBE`, so it needs
  `select` on the object and it describes the rewritten relation, not the physical table.
- **Allowing `PRAGMA_STATEMENT` through the gate does not allow PRAGMA.** Two names are answered by
  rewriting them into a `SELECT`; every other name is denied by name, and a setting written as
  `PRAGMA x='y'` parses as a `SET` statement, which the gate refuses as before.
- `pk` in a `table_info` answer is always `false`, because the relation a principal reads is a
  projection and a projection has no primary key. Honest for what it describes.

## Testing

`test/sql/acl_show_surface.test` (87 assertions): `SHOW DATABASES` listing the granted catalogs and no
physical one; `SHOW SCHEMAS` in its three-column shape with `current` true only for the MAIN catalog's
`main`; `SHOW ALL TABLES` in its six-column shape, carrying only the columns the role reads and none
of the objects it cannot see; `SHOW TABLES` and `SHOW TABLES FROM` unchanged; `SHOW VARIABLES` empty
in the right shape; `PRAGMA table_info` in DuckDB's shape for a bare and a schema-qualified name,
refused for a hidden name and for a physical one; `PRAGMA show_tables`; other PRAGMAs refused by name;
and a role that may see nothing seeing nothing through any of them.

## Alternatives considered

- **Keep answering everything with the table listing.** It is what a `SHOW` form got before, and it is
  wrong in a way a client cannot detect.
- **Refuse the forms we do not answer.** For `SHOW DATABASES`/`SHOW SCHEMAS` the ACL genuinely knows
  the answer, so refusing would hide something the principal is entitled to. Only `SHOW VARIABLES` has
  nothing to say, and there an empty result says it.
- **Answer `PRAGMA table_info` from the `columns` listing.** Simpler SQL, but a name the principal
  cannot see comes back as an empty result instead of a refusal, which reads as "no columns".

## Follow-ups

- `PRAGMA database_list`, `PRAGMA show_databases` and the `pragma_table_info(…)` *table function* are
  still refused. Each is the same rewrite as `table_info`; they were left out because nothing has
  asked for them, not because they are hard.
- `SHOW ALL TABLES` reports `temporary` as `false` for everything. A principal has no temporary
  relations today (spec 003's statement gate refuses `CREATE TEMP TABLE`), so it is true until client
  ingest lands.
