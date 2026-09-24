-- duckdb-acl schema migration: v14 -> v15 (spec 085, resource groups).
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- Two new tables, empty: no role is in a group until an operator puts it there.
CREATE TABLE IF NOT EXISTS acl."resource_groups"("group" VARCHAR PRIMARY KEY, "window_start" BIGINT, "window_max" BIGINT, "batch_bytes" BIGINT, "max_result_rows" BIGINT, "queue_priority" BIGINT, "max_sessions" BIGINT, "comment" VARCHAR);
CREATE TABLE IF NOT EXISTS acl."role_resource_groups"("role" VARCHAR, "group" VARCHAR, PRIMARY KEY ("role", "group"));
UPDATE acl."meta" SET "value" = '15' WHERE "key" = 'schema_version';
