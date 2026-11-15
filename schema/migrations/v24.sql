-- duckdb-acl schema migration: v23 -> v24 (spec 167, the versions of a time-travel table a grant admits).
-- min_reader: 24 - a grant's VERSIONS limits what a role reads; a v23 build would ignore the column and serve every version
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- versions: the grant's VERSIONS clause as stored (CURRENT, ANY, AT (…), BETWEEN … AND …); NULL = not stated (an
-- object grant takes its catalog grant's, a catalog grant every version). Existing grants state nothing.
ALTER TABLE acl."role_catalogs" ADD COLUMN IF NOT EXISTS "versions" VARCHAR;
ALTER TABLE acl."role_object_caps" ADD COLUMN IF NOT EXISTS "versions" VARCHAR;
DELETE FROM acl."meta" WHERE "key" = 'min_reader_version';
INSERT INTO acl."meta" VALUES ('min_reader_version', '24');
UPDATE acl."meta" SET "value" = '24' WHERE "key" = 'schema_version';
