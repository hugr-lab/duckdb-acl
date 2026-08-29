-- duckdb-acl schema migration: v10 -> v11 (spec 048, the declared shape of an object).
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need
-- changing (a key column is indexed, so SQL Server wants NVARCHAR(255), not MAX).
ALTER TABLE acl."relation_columns" ADD COLUMN "nullable" BOOLEAN;
ALTER TABLE acl."object_columns" ADD COLUMN "nullable" BOOLEAN;
CREATE TABLE acl."keys"("vcat" VARCHAR, "vname" VARCHAR, "kind" VARCHAR, "pos" INTEGER, "column" VARCHAR, PRIMARY KEY ("vcat", "vname", "kind", "pos"));
UPDATE acl."meta" SET "value" = '11' WHERE "key" = 'schema_version';
