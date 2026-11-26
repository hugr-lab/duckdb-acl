-- duckdb-acl schema migration: v28 -> v29 (spec 181, a session's scripts).
-- min_reader: 28 - v29 only appends columns; a v28 build ignores them (it runs no session script) and, inside the window, never writes (spec 094)
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- session_script / session_on_error: the SQL a session runs when it opens, as written, and 'fail' (NULL) or
-- 'continue' - a role's, a resource group's and a role's grant of a group. Existing catalogs have none.
ALTER TABLE acl."roles" ADD COLUMN IF NOT EXISTS "session_script" VARCHAR;
ALTER TABLE acl."roles" ADD COLUMN IF NOT EXISTS "session_on_error" VARCHAR;
ALTER TABLE acl."resource_groups" ADD COLUMN IF NOT EXISTS "session_script" VARCHAR;
ALTER TABLE acl."resource_groups" ADD COLUMN IF NOT EXISTS "session_on_error" VARCHAR;
ALTER TABLE acl."role_resource_groups" ADD COLUMN IF NOT EXISTS "session_script" VARCHAR;
ALTER TABLE acl."role_resource_groups" ADD COLUMN IF NOT EXISTS "session_on_error" VARCHAR;
UPDATE acl."meta" SET "value" = '29' WHERE "key" = 'schema_version';
