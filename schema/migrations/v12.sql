-- duckdb-acl schema migration: v11 -> v12 (spec 064, the Flight door's auth discovery + password handshake).
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- client_id is the app registration the node runs the password grant as (and what discovery
-- advertises for a driver's own flow); client_secret only for a confidential client. Both optional.
ALTER TABLE acl."issuers" ADD COLUMN "client_id" VARCHAR;
ALTER TABLE acl."issuers" ADD COLUMN "client_secret" VARCHAR;
UPDATE acl."meta" SET "value" = '12' WHERE "key" = 'schema_version';
