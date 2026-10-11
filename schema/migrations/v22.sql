-- duckdb-acl schema migration: v21 -> v22 (spec 120.5, who created an object).
-- min_reader: 21 - v22 adds a nullable column at the end of four tables; a v21 build reads by name and, inside the window, never writes (spec 094)
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- created_by: the author of an object's first definition - `<issuer>|<subject>` for a token, the role for a gateway's
-- ACL ROLE, NULL for the operator and the anonymous gateway. created_roles: the author's roles (csv) when the source
-- gate bound it (an administrator below policy, spec 118.3) - what acl_check_catalog's source_not_granted judges.
-- Existing rows stay NULL: nobody recorded who made them.
ALTER TABLE acl."relations" ADD COLUMN IF NOT EXISTS "created_by" VARCHAR;
ALTER TABLE acl."relations" ADD COLUMN IF NOT EXISTS "created_roles" VARCHAR;
ALTER TABLE acl."schemas" ADD COLUMN IF NOT EXISTS "created_by" VARCHAR;
ALTER TABLE acl."schemas" ADD COLUMN IF NOT EXISTS "created_roles" VARCHAR;
ALTER TABLE acl."functions" ADD COLUMN IF NOT EXISTS "created_by" VARCHAR;
ALTER TABLE acl."functions" ADD COLUMN IF NOT EXISTS "created_roles" VARCHAR;
ALTER TABLE acl."references" ADD COLUMN IF NOT EXISTS "created_by" VARCHAR;
ALTER TABLE acl."references" ADD COLUMN IF NOT EXISTS "created_roles" VARCHAR;
UPDATE acl."meta" SET "value" = '22' WHERE "key" = 'schema_version';
