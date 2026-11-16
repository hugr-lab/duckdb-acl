-- duckdb-acl schema migration: v24 -> v25 (spec 158, an object grant's columns and masks).
-- min_reader: 25 - an object grant's masks are a column of their own; a v24 build would ignore it and serve the
-- column unmasked
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- masks: the grant's MASK items as stored ("<column>" AS <expression>, …); NULL = none. A catalog grant's columns
-- are no longer written: a stored one refuses the reads under that grant (acl_check_catalog names it).
ALTER TABLE acl."role_object_caps" ADD COLUMN IF NOT EXISTS "masks" VARCHAR;
DELETE FROM acl."meta" WHERE "key" = 'min_reader_version';
INSERT INTO acl."meta" VALUES ('min_reader_version', '25');
UPDATE acl."meta" SET "value" = '25' WHERE "key" = 'schema_version';
