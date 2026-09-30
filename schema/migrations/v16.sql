-- duckdb-acl schema migration: v15 -> v16 (spec 093, the cluster profile).
-- min_reader: 15 - v16 only adds the cluster profile's tables; a v15 build that ignores them serves the same policy (spec 094)
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- Two new tables, empty, and the config_version counter at 0: no node's bootstrap is described yet.
CREATE TABLE IF NOT EXISTS acl."cluster_items"("scope" VARCHAR, "kind" VARCHAR, "name" VARCHAR, "spec" VARCHAR, "class" VARCHAR, "version" BIGINT, "pos" BIGINT, "comment" VARCHAR, PRIMARY KEY ("scope", "kind", "name"));
CREATE TABLE IF NOT EXISTS acl."cluster_deps"("scope" VARCHAR, "name" VARCHAR, "depends_on" VARCHAR, PRIMARY KEY ("scope", "name", "depends_on"));
INSERT INTO acl."meta" SELECT 'config_version', '0' WHERE NOT EXISTS (SELECT 1 FROM acl."meta" WHERE "key" = 'config_version');
DELETE FROM acl."meta" WHERE "key" = 'min_reader_version';
INSERT INTO acl."meta" VALUES ('min_reader_version', '15');
UPDATE acl."meta" SET "value" = '16' WHERE "key" = 'schema_version';
