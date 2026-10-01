-- duckdb-acl schema migration: v17 -> v18 (spec 096, a node's resource group and the default group).
-- min_reader: 17 - v18 only adds is_default; a v17 build that ignores it has no placement at all, so it admits no session it did not already admit (spec 094)
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- No group is the default after this step: an ungrouped principal is served by ungrouped nodes until
-- an operator marks one (CREATE RESOURCE GROUP ... DEFAULT / ALTER RESOURCE GROUP g SET DEFAULT).
ALTER TABLE acl."resource_groups" ADD COLUMN "is_default" BOOLEAN;
DELETE FROM acl."meta" WHERE "key" = 'min_reader_version';
INSERT INTO acl."meta" VALUES ('min_reader_version', '17');
UPDATE acl."meta" SET "value" = '18' WHERE "key" = 'schema_version';
