-- duckdb-acl schema migration: v12 -> v13 (the 2026-09-03 release review).
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- `schema_aliases` was the pre-spec-015 alias table, kept "in step for one version so a rollback still
-- resolves" after `schemas` replaced it - written on every schema write, read by nothing in table mode
-- (the function-driver SLOT of the same name is a callback contract and is untouched). No release ever
-- shipped it, so there is no version to roll back to; it goes.
DROP TABLE IF EXISTS acl."schema_aliases";
UPDATE acl."meta" SET "value" = '13' WHERE "key" = 'schema_version';
