-- duckdb-acl schema migration: v18 -> v19 (spec 099, types under the ACL).
-- min_reader: 18 - v19 adds a relation's type policy and its type facts; a v18 build ignores them and exposes the source's types as they are (alias types, ENUMs) - what it already did (spec 094)
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- No relation has type facts after this step: they are probed when a relation is written or refreshed
-- (ACL ADMIN ANALYZE / acl_refresh_schema), and acl_check_catalog reports the ones still to probe.
ALTER TABLE acl."relations" ADD COLUMN "alias_types" VARCHAR;
ALTER TABLE acl."relations" ADD COLUMN "enum_types" VARCHAR;
CREATE TABLE IF NOT EXISTS acl."relation_types"("vcat" VARCHAR, "vname" VARCHAR, "column" VARCHAR, "as_base" VARCHAR, "as_varchar" VARCHAR, "as_both" VARCHAR, PRIMARY KEY ("vcat", "vname", "column"));
DELETE FROM acl."meta" WHERE "key" = 'min_reader_version';
INSERT INTO acl."meta" VALUES ('min_reader_version', '18');
UPDATE acl."meta" SET "value" = '19' WHERE "key" = 'schema_version';
