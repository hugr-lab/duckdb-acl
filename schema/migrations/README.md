# Schema migrations

The steps that take an existing policy catalog from one schema version to the next. The extension
does not apply them itself: `acl_use_db(..., true)` refuses a catalog with an older stamp by
version and points here - an operator applies the steps by hand, in order, against the database
that holds the schema. A fresh catalog is always created from [`../acl_schema.sql`](../acl_schema.sql)
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
- Every step is generated from `../policy_schema.sql` by `make schema`, like everything else here —
  the source file is where a new column is added, and the step records how an existing catalog gets
  there.

## Why not "add the column if it is missing"

That is what the extension used to do, and it reads as robust: replay every `ALTER … IF NOT EXISTS`
on every init and let the ones already applied fall through. Two things are wrong with it. It grows
without bound — every version's statements run forever — and `IF NOT EXISTS` is not universal: the
SQL Server scanner drops the clause, so the replay failed outright there (spec 033). A version
number the catalog carries is both cheaper and portable.
