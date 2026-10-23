-- duckdb-acl schema migration: v22 -> v23 (spec 143, a virtual comment for an alias relation's column).
-- min_reader: 21 - v23 only adds column_comments; a v22 build ignores it and, inside the window, never writes (spec 094)
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- column_comments: a column's virtual comment where the object stores no column list (an alias relation, its columns
-- the source's). Existing catalogs have none.
CREATE TABLE IF NOT EXISTS acl."column_comments"("vcat" VARCHAR, "vname" VARCHAR, "column_name" VARCHAR, "comment" VARCHAR, PRIMARY KEY ("vcat", "vname", "column_name"));
UPDATE acl."meta" SET "value" = '23' WHERE "key" = 'schema_version';
