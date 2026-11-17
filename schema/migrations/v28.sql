-- duckdb-acl schema migration: v27 -> v28 (spec 172, values an object computes on a write).
-- min_reader: 28 - an older build would write through the object without computing them (a tenant left to the client)
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- relation_write_values: per relation, what an INSERT ('insert') or an UPDATE ('update') sets by itself - the column
-- by its virtual name, the expression as duckdb prints it (`new.<column>` the value this write gives a column).
CREATE TABLE IF NOT EXISTS acl."relation_write_values"("vcat" VARCHAR, "vname" VARCHAR, "verb" VARCHAR, "pos" INTEGER, "column" VARCHAR, "expr" VARCHAR, PRIMARY KEY ("vcat", "vname", "verb", "pos"));
DELETE FROM acl."meta" WHERE "key" = 'min_reader_version';
INSERT INTO acl."meta" VALUES ('min_reader_version', '28');
UPDATE acl."meta" SET "value" = '28' WHERE "key" = 'schema_version';
