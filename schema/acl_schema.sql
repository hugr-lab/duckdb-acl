-- duckdb-acl policy schema (spec 006), generated from schema/policy_schema.sql.
-- Do not edit: run `make schema` after changing the source (spec 034).
--
-- duckdb dialect, ready to run as it stands: it creates the schema `acl` in the database you
-- run it against, which is what `acl_use_db('<db>', 'acl', true)` would have created. Pass the
-- same schema name to acl_use_db afterwards, with init disabled, and the extension will use it.
--
-- It is the schema as it stands - the migrations the extension also carries are for catalogs
-- an older version created, and a schema applied from here needs none of them.
--
-- For another engine, translate it - the SQL is plain, and a translator (sqlglot and friends)
-- handles it. Two things a target may need changing:
--   * a key column (VARCHAR below, ACL_KEY_TEXT in the source) is indexed, so SQL Server needs
--     it bounded - NVARCHAR(255) rather than NVARCHAR(MAX), which cannot carry an index;
--   * `IF NOT EXISTS` on CREATE TABLE / ADD COLUMN is not universal - T-SQL guards instead.

CREATE SCHEMA IF NOT EXISTS acl;

CREATE TABLE IF NOT EXISTS acl."meta"("key" VARCHAR PRIMARY KEY, "value" VARCHAR);

CREATE TABLE IF NOT EXISTS acl."catalogs"("vcat" VARCHAR PRIMARY KEY, "comment" VARCHAR);

CREATE TABLE IF NOT EXISTS acl."relations"("vcat" VARCHAR, "vname" VARCHAR, "form" VARCHAR, "phys" VARCHAR, "view_sql" VARCHAR, "rls" VARCHAR, "comment" VARCHAR, "origin" VARCHAR, "rls_checked" BOOLEAN, PRIMARY KEY ("vcat", "vname"));

CREATE TABLE IF NOT EXISTS acl."relation_columns"("vcat" VARCHAR, "vname" VARCHAR, "pos" INTEGER, "name" VARCHAR, "expr" VARCHAR, "nullable" BOOLEAN, PRIMARY KEY ("vcat", "vname", "pos"));

CREATE TABLE IF NOT EXISTS acl."functions"("vcat" VARCHAR, "vname" VARCHAR, "kind" VARCHAR, "form" VARCHAR, "target" VARCHAR, "template" VARCHAR, "comment" VARCHAR, "params" VARCHAR, PRIMARY KEY ("vcat", "vname", "kind"));

CREATE TABLE IF NOT EXISTS acl."roles"("role" VARCHAR PRIMARY KEY, "comment" VARCHAR);

CREATE TABLE IF NOT EXISTS acl."role_claims"("role" VARCHAR, "claim" VARCHAR, "value" VARCHAR, PRIMARY KEY ("role", "claim"));

CREATE TABLE IF NOT EXISTS acl."role_catalogs"("role" VARCHAR, "vcat" VARCHAR, "is_main" BOOLEAN, "caps" VARCHAR, "rls" VARCHAR, "columns" VARCHAR, "rls_checked" BOOLEAN, PRIMARY KEY ("role", "vcat"));

CREATE TABLE IF NOT EXISTS acl."role_object_caps"("role" VARCHAR, "vcat" VARCHAR, "vname" VARCHAR, "caps" VARCHAR, "rls" VARCHAR, "columns" VARCHAR, "rls_checked" BOOLEAN, PRIMARY KEY ("role", "vcat", "vname"));

-- '' as role/kind means "global"/"any kind": NULL cannot be part of the primary key
CREATE TABLE IF NOT EXISTS acl."function_gate"("role" VARCHAR, "name" VARCHAR, "kind" VARCHAR, "allowed" BOOLEAN, PRIMARY KEY ("role", "name", "kind"));

CREATE TABLE IF NOT EXISTS acl."issuers"("issuer" VARCHAR PRIMARY KEY, "keys_json" VARCHAR, "audiences" VARCHAR, "algs" VARCHAR, "role_claim" VARCHAR, "claim_map" VARCHAR, "jwks_uri" VARCHAR, "client_id" VARCHAR, "client_secret" VARCHAR);

-- '' as vcat means "every catalog": NULL cannot be part of the primary key
CREATE TABLE IF NOT EXISTS acl."admins"("role" VARCHAR PRIMARY KEY, "scope" VARCHAR, "vcat" VARCHAR);

CREATE TABLE IF NOT EXISTS acl."role_mappings"("issuer" VARCHAR, "source" VARCHAR, "external_value" VARCHAR, "role" VARCHAR, PRIMARY KEY ("issuer", "source", "external_value", "role"));

-- spec 010 (schema v2): comments, and the column schema of every object - declared by an
-- admin or derived by binding the template at write time (a query-defined object has no
-- physical row to read names and types from). Runs after every CREATE TABLE above.
CREATE TABLE IF NOT EXISTS acl."object_columns"("vcat" VARCHAR, "vname" VARCHAR, "kind" VARCHAR, "pos" INTEGER, "name" VARCHAR, "type" VARCHAR, "comment" VARCHAR, "derived" BOOLEAN, "nullable" BOOLEAN, PRIMARY KEY ("vcat", "vname", "kind", "pos"));

CREATE TABLE IF NOT EXISTS acl."schemas"("vcat" VARCHAR, "path" VARCHAR, "phys_path" VARCHAR, "comment" VARCHAR, "origin" VARCHAR, PRIMARY KEY ("vcat", "path"));

CREATE TABLE IF NOT EXISTS acl."role_schemas"("role" VARCHAR, "vcat" VARCHAR, "schema_path" VARCHAR, "caps" VARCHAR, "inherited" BOOLEAN, "comment" VARCHAR, "into" VARCHAR, "virtual_only" BOOLEAN, PRIMARY KEY ("role", "vcat", "schema_path"));

-- a record dropped on purpose must not come back on the next REFRESH
CREATE TABLE IF NOT EXISTS acl."schema_dropped"("vcat" VARCHAR, "path" VARCHAR, "name" VARCHAR, PRIMARY KEY ("vcat", "path", "name"));

-- and the record is a hint an agent reads. The columns live in their own table so that
-- visibility is an anti-join rather than the parsing of a packed string.
CREATE TABLE IF NOT EXISTS acl."references"("vcat" VARCHAR, "name" VARCHAR, "from_vname" VARCHAR, "to_vname" VARCHAR, "to_kind" VARCHAR, "expr" VARCHAR, "cardinality" VARCHAR, "optional" BOOLEAN, "join_method" VARCHAR, "comment" VARCHAR, PRIMARY KEY ("vcat", "name"));

CREATE TABLE IF NOT EXISTS acl."reference_columns"("vcat" VARCHAR, "name" VARCHAR, "pos" INTEGER, "side" VARCHAR, "column" VARCHAR, "param" VARCHAR, PRIMARY KEY ("vcat", "name", "pos", "side"));

-- spec 048 (schema v11): the declared shape - a primary key an admin states about a virtual
-- object (a table, a view or a table function; `kind` mirrors object_columns). Declared, never
-- enforced; visible only when the object and every named column are.
CREATE TABLE IF NOT EXISTS acl."keys"("vcat" VARCHAR, "vname" VARCHAR, "kind" VARCHAR, "pos" INTEGER, "column" VARCHAR, PRIMARY KEY ("vcat", "vname", "kind", "pos"));

-- add a computed one the object never had - and a listing that cannot see those describes
-- something the role does not read.
CREATE TABLE IF NOT EXISTS acl."grant_columns"("role" VARCHAR, "vcat" VARCHAR, "vname" VARCHAR, "pos" INTEGER, "name" VARCHAR, "type" VARCHAR, PRIMARY KEY ("role", "vcat", "vname", "pos"));

INSERT INTO acl."meta" SELECT 'schema_version', '13' WHERE NOT EXISTS (SELECT 1 FROM acl."meta" WHERE "key" = 'schema_version');

INSERT INTO acl."meta" SELECT 'policy_version', '1' WHERE NOT EXISTS (SELECT 1 FROM acl."meta" WHERE "key" = 'policy_version');
