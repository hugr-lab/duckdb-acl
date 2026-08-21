-- The managed policy schema of duckdb-acl (spec 006), and the only place it is written down.
--
-- This file is the source of truth. `make schema` renders it into
--   src/include/acl_schema_sql.hpp   the statements the extension runs, placeholders intact
--   schema/acl_schema.sql            the same with names resolved, ready to apply by hand
-- so a hand-applied schema and the one the extension creates cannot drift apart (spec 034).
--
-- Placeholders, substituted by whoever renders this:
--   <schema>       the qualified schema  ("mydb"."acl")
--   <table>        a table in it         ("mydb"."acl"."relations")
--   ACL_KEY_TEXT   the type of a key column - a plain text type everywhere except SQL Server,
--                  whose scanner maps every VARCHAR to NVARCHAR(MAX) and then cannot index it
--                  (spec 033). Only columns that take part in a primary key carry it.
--
-- Only this dialect is kept. Translating to another engine is left to whoever applies it, or to a
-- later step through a real translator - the SQL is plain, and a hand-rolled per-dialect renderer
-- would be a second thing to keep correct for no gain.
--
-- Every table carries a primary key: sources without rowids need one for DELETE/UPDATE.
--
-- The stamp is only ever *inserted* here: bringing an existing one up to date is a decision about
-- versions, which the extension makes in C++ where a value that is not a number is a case rather
-- than an exception (spec 034).

-- @section schema
-- The tables as they are now: a catalog is created complete, in one statement each, and stamped with
-- the schema version at the end. There are no migrations yet - see schema/migrations/README.md for
-- the contract they will follow.

CREATE SCHEMA IF NOT EXISTS <schema>;

CREATE TABLE IF NOT EXISTS <meta>("key" ACL_KEY_TEXT PRIMARY KEY, "value" VARCHAR);

CREATE TABLE IF NOT EXISTS <catalogs>("vcat" ACL_KEY_TEXT PRIMARY KEY, "comment" VARCHAR);

CREATE TABLE IF NOT EXISTS <relations>("vcat" ACL_KEY_TEXT, "vname" ACL_KEY_TEXT, "form" VARCHAR, "phys" VARCHAR, "view_sql" VARCHAR, "rls" VARCHAR, "comment" VARCHAR, "origin" VARCHAR, "rls_checked" BOOLEAN, PRIMARY KEY ("vcat", "vname"));

CREATE TABLE IF NOT EXISTS <relation_columns>("vcat" ACL_KEY_TEXT, "vname" ACL_KEY_TEXT, "pos" INTEGER, "name" VARCHAR, "expr" VARCHAR, PRIMARY KEY ("vcat", "vname", "pos"));

CREATE TABLE IF NOT EXISTS <schema_aliases>("vcat" ACL_KEY_TEXT, "alias_path" ACL_KEY_TEXT, "phys_path" VARCHAR, PRIMARY KEY ("vcat", "alias_path"));

CREATE TABLE IF NOT EXISTS <functions>("vcat" ACL_KEY_TEXT, "vname" ACL_KEY_TEXT, "kind" ACL_KEY_TEXT, "form" VARCHAR, "target" VARCHAR, "template" VARCHAR, "comment" VARCHAR, "params" VARCHAR, PRIMARY KEY ("vcat", "vname", "kind"));

CREATE TABLE IF NOT EXISTS <roles>("role" ACL_KEY_TEXT PRIMARY KEY, "comment" VARCHAR);

CREATE TABLE IF NOT EXISTS <role_claims>("role" ACL_KEY_TEXT, "claim" ACL_KEY_TEXT, "value" VARCHAR, PRIMARY KEY ("role", "claim"));

CREATE TABLE IF NOT EXISTS <role_catalogs>("role" ACL_KEY_TEXT, "vcat" ACL_KEY_TEXT, "is_main" BOOLEAN, "caps" VARCHAR, "rls" VARCHAR, "columns" VARCHAR, "rls_checked" BOOLEAN, PRIMARY KEY ("role", "vcat"));

CREATE TABLE IF NOT EXISTS <role_object_caps>("role" ACL_KEY_TEXT, "vcat" ACL_KEY_TEXT, "vname" ACL_KEY_TEXT, "caps" VARCHAR, "rls" VARCHAR, "columns" VARCHAR, "rls_checked" BOOLEAN, PRIMARY KEY ("role", "vcat", "vname"));

-- '' as role/kind means "global"/"any kind": NULL cannot be part of the primary key
CREATE TABLE IF NOT EXISTS <function_gate>("role" ACL_KEY_TEXT, "name" ACL_KEY_TEXT, "kind" ACL_KEY_TEXT, "allowed" BOOLEAN, PRIMARY KEY ("role", "name", "kind"));

CREATE TABLE IF NOT EXISTS <issuers>("issuer" ACL_KEY_TEXT PRIMARY KEY, "keys_json" VARCHAR, "audiences" VARCHAR, "algs" VARCHAR, "role_claim" VARCHAR, "claim_map" VARCHAR, "jwks_uri" VARCHAR);

-- '' as vcat means "every catalog": NULL cannot be part of the primary key
CREATE TABLE IF NOT EXISTS <admins>("role" ACL_KEY_TEXT PRIMARY KEY, "scope" VARCHAR, "vcat" VARCHAR);

CREATE TABLE IF NOT EXISTS <role_mappings>("issuer" ACL_KEY_TEXT, "source" ACL_KEY_TEXT, "external_value" ACL_KEY_TEXT, "role" ACL_KEY_TEXT, PRIMARY KEY ("issuer", "source", "external_value", "role"));

-- spec 010 (schema v2): comments, and the column schema of every object - declared by an
-- admin or derived by binding the template at write time (a query-defined object has no
-- physical row to read names and types from). Runs after every CREATE TABLE above.
CREATE TABLE IF NOT EXISTS <object_columns>("vcat" ACL_KEY_TEXT, "vname" ACL_KEY_TEXT, "kind" ACL_KEY_TEXT, "pos" INTEGER, "name" VARCHAR, "type" VARCHAR, "comment" VARCHAR, "derived" BOOLEAN, PRIMARY KEY ("vcat", "vname", "kind", "pos"));

CREATE TABLE IF NOT EXISTS <schemas>("vcat" ACL_KEY_TEXT, "path" ACL_KEY_TEXT, "phys_path" VARCHAR, "comment" VARCHAR, "origin" VARCHAR, PRIMARY KEY ("vcat", "path"));

CREATE TABLE IF NOT EXISTS <role_schemas>("role" ACL_KEY_TEXT, "vcat" ACL_KEY_TEXT, "schema_path" ACL_KEY_TEXT, "caps" VARCHAR, "inherited" BOOLEAN, "comment" VARCHAR, "into" VARCHAR, "virtual_only" BOOLEAN, PRIMARY KEY ("role", "vcat", "schema_path"));

-- a record dropped on purpose must not come back on the next REFRESH
CREATE TABLE IF NOT EXISTS <schema_dropped>("vcat" ACL_KEY_TEXT, "path" ACL_KEY_TEXT, "name" ACL_KEY_TEXT, PRIMARY KEY ("vcat", "path", "name"));

-- and the record is a hint an agent reads. The columns live in their own table so that
-- visibility is an anti-join rather than the parsing of a packed string.
CREATE TABLE IF NOT EXISTS <references>("vcat" ACL_KEY_TEXT, "name" ACL_KEY_TEXT, "from_vname" VARCHAR, "to_vname" VARCHAR, "to_kind" VARCHAR, "expr" VARCHAR, "cardinality" VARCHAR, "optional" BOOLEAN, "join_method" VARCHAR, "comment" VARCHAR, PRIMARY KEY ("vcat", "name"));

CREATE TABLE IF NOT EXISTS <reference_columns>("vcat" ACL_KEY_TEXT, "name" ACL_KEY_TEXT, "pos" INTEGER, "side" ACL_KEY_TEXT, "column" VARCHAR, "param" VARCHAR, PRIMARY KEY ("vcat", "name", "pos", "side"));

-- add a computed one the object never had - and a listing that cannot see those describes
-- something the role does not read.
CREATE TABLE IF NOT EXISTS <grant_columns>("role" ACL_KEY_TEXT, "vcat" ACL_KEY_TEXT, "vname" ACL_KEY_TEXT, "pos" INTEGER, "name" VARCHAR, "type" VARCHAR, PRIMARY KEY ("role", "vcat", "vname", "pos"));

INSERT INTO <meta> SELECT 'schema_version', '10' WHERE NOT EXISTS (SELECT 1 FROM <meta> WHERE "key" = 'schema_version');


INSERT INTO <meta> SELECT 'policy_version', '1' WHERE NOT EXISTS (SELECT 1 FROM <meta> WHERE "key" = 'policy_version');
