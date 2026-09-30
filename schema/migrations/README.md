# Schema migrations

The steps that take an existing policy catalog from one schema version to the next. Since spec 094
the build **embeds** them (`make schema` renders them into `src/acl_schema_sql.hpp`) and applies them
with `acl_migrate_catalog(db[, schema])`, every step above the catalog's version in one transaction.
The files stay the source, and what an operator applies by hand on another engine. A fresh catalog is always created from [`../acl_schema.sql`](../acl_schema.sql)
complete and needs none of them. `v11.sql` (spec 048) is the first step.

## The contract

- The schema carries its version in its own `meta` table: `('schema_version', '<n>')`. Both
  `acl_schema.sql` and the extension's own init write it, so a catalog always says what it is.
- A version step is one file here, named `v<n>.sql`, holding the statements that take a catalog from
  `<n-1>` to `<n>` — and ending with the stamp that makes it `<n>`:

  ```sql
  ALTER TABLE acl."relations" ADD COLUMN "something" VARCHAR;
  UPDATE acl."meta" SET "value" = '11' WHERE "key" = 'schema_version';
  ```

- Applying is by version, not by inspection: read `meta.schema_version`, apply every `v<n>.sql` with
  `<n>` greater than it, in order. A catalog already at the current version runs nothing — which is
  what makes re-running the init cheap and safe.
- **`acl_schema.sql` always creates the current version complete.** A fresh catalog never replays the
  history; a migrated one never diverges from a fresh one, because each step is written to land on
  exactly what the schema file would have created. That is the invariant to check when adding a step:
  a catalog migrated from `<n-1>` and one created fresh at `<n>` must have the same columns in the
  same order.
- A step is written by hand alongside the change to `../policy_schema.sql` (the source file is where
  a new column is added; `make schema` regenerates the complete current schema, never the steps), and
  **the invariant above is checked, not assumed**: `make schema-check` builds a catalog from the
  schema file the `main` branch ships, applies every step above its version, and diffs the column
  shape of every `acl` table against a catalog created fresh from the current file.

## The compatibility window (spec 094)

Every step declares, in its header, the oldest build that may still read the catalog it produces:

```sql
-- min_reader: 15 - v16 only adds the cluster profile's tables; a v15 build that ignores them serves the same policy (spec 094)
```

The extension stamps it into `meta.min_reader_version`. A build older than the catalog but at or
above that number **serves from it and never writes** (a write would rewrite rows without what the
newer step added). A build below it refuses. This is what makes a rolling upgrade possible: migrate
first, and the old nodes keep serving until they are replaced.

**The number is the author's judgment, not a formula.** The test is whether an older build that
ignores what the step adds can ever admit more than the new build would:
- A new table or column the old build never reads is usually safe.
- A new column that narrows access (a restriction the new build enforces) is not: an old node
  ignoring it would widen access. Such a step declares its own version.

The rules for a step that keeps older readers:
- It only adds: tables, or columns appended at the end.
- It never renames, drops or retypes. Reads name their columns, but an old build's `INSERT … VALUES`
  is positional; writes are refused anyway.
- `make schema` refuses a step without a declaration, and `policy_schema.sql`'s own
  `min_reader_version` must equal the latest step's.

## Why not "add the column if it is missing"

That is what the extension used to do, and it reads as robust: replay every `ALTER … IF NOT EXISTS`
on every init and let the ones already applied fall through. Two things are wrong with it. It grows
without bound — every version's statements run forever — and `IF NOT EXISTS` is not universal: the
SQL Server scanner drops the clause, so the replay failed outright there (spec 033). A version
number the catalog carries is both cheaper and portable.
