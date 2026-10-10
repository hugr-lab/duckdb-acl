-- duckdb-acl schema migration: v20 -> v21 (spec 117, the platform catalog).
-- min_reader: 21 - v21 reads `admins` as a set of bundles (several rows per role, `policy` beside `manage`) and holds point grants on platform in platform_grants; a v20 build would read a role's second bundle as its only one and ignore the point grants, so it must not serve a v21 catalog (spec 094)
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- `platform` is the reserved name of the system catalog (spec 117): the step refuses while a virtual
-- catalog - or a grant on one - carries it; rename it (or drop it) first, then migrate.
SELECT CASE WHEN count(*) > 0 THEN error('v21 reserves the catalog name platform for the system catalog of administration (spec 117), and the policy uses it: ' || string_agg(DISTINCT source, ', ' ORDER BY source) || ' - rename or drop that catalog, then migrate') END FROM (SELECT 'catalogs' AS source FROM acl."catalogs" WHERE translate("vcat", 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') IN ('platform', '"platform"') UNION ALL SELECT 'role_catalogs' AS source FROM acl."role_catalogs" WHERE translate("vcat", 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') IN ('platform', '"platform"') UNION ALL SELECT 'relations' AS source FROM acl."relations" WHERE translate("vcat", 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') IN ('platform', '"platform"') UNION ALL SELECT 'functions' AS source FROM acl."functions" WHERE translate("vcat", 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') IN ('platform', '"platform"') UNION ALL SELECT 'schemas' AS source FROM acl."schemas" WHERE translate("vcat", 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') IN ('platform', '"platform"') UNION ALL SELECT 'admins' AS source FROM acl."admins" WHERE translate("vcat", 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') IN ('platform', '"platform"'));
-- admins: the key was the role alone (one scope per role); it is the row now. Re-created, the rows
-- carried over as they are - a spec 009 row reads as its bundles (`manage` = policy + observe, a
-- catalog-scoped `manage` = that catalog), so nothing is rewritten.
CREATE TABLE acl."admins_previous"("role" VARCHAR, "scope" VARCHAR, "vcat" VARCHAR);
INSERT INTO acl."admins_previous" SELECT "role", coalesce("scope", ''), coalesce("vcat", '') FROM acl."admins";
DROP TABLE acl."admins";
CREATE TABLE acl."admins"("role" VARCHAR, "scope" VARCHAR, "vcat" VARCHAR, PRIMARY KEY ("role", "scope", "vcat"));
INSERT INTO acl."admins" SELECT DISTINCT "role", "scope", "vcat" FROM acl."admins_previous";
DROP TABLE acl."admins_previous";
CREATE TABLE IF NOT EXISTS acl."platform_grants"("role" VARCHAR, "object" VARCHAR, "kind" VARCHAR, "allowed" BOOLEAN NOT NULL DEFAULT true, PRIMARY KEY ("role", "object", "kind"));
DELETE FROM acl."meta" WHERE "key" = 'min_reader_version';
INSERT INTO acl."meta" VALUES ('min_reader_version', '21');
UPDATE acl."meta" SET "value" = '21' WHERE "key" = 'schema_version';
