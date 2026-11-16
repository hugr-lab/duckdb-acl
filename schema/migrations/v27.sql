-- duckdb-acl schema migration: v26 -> v27 (spec 158 stage 3, spec 102's machinery removed).
-- min_reader: 27 - grant_columns is gone; a v26 build's listings still read it
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- grant_columns held what a grant's projection produced (spec 026); since spec 158 a grant names, types and adds no
-- column, and nothing wrote it.
DROP TABLE IF EXISTS acl."grant_columns";
DELETE FROM acl."meta" WHERE "key" = 'min_reader_version';
INSERT INTO acl."meta" VALUES ('min_reader_version', '27');
UPDATE acl."meta" SET "value" = '27' WHERE "key" = 'schema_version';
