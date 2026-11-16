-- duckdb-acl schema migration: v25 -> v26 (spec 169, a principal's view reads under its reader's grants).
-- min_reader: 26 - a principal's view keeps its query in a column of its own; a v25 build would ignore it and read the
-- view with its author's policy
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- query: a principal's view as written, its relations qualified to their canonical virtual keys; NULL = an operator's
-- view (view_sql is what it reads). A principal's view's view_sql is its author's resolution - its shape only.
ALTER TABLE acl."relations" ADD COLUMN IF NOT EXISTS "query" VARCHAR;
DELETE FROM acl."meta" WHERE "key" = 'min_reader_version';
INSERT INTO acl."meta" VALUES ('min_reader_version', '26');
UPDATE acl."meta" SET "value" = '26' WHERE "key" = 'schema_version';
