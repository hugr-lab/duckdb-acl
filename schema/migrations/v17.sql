-- duckdb-acl schema migration: v16 -> v17 (spec 095, issuers and clients).
-- min_reader: 17 - the identity tables are rebuilt; a v16 build reads columns that are gone (spec 094: the window is declared per step, never assumed)
-- Run against the database that holds the `acl` policy schema, then re-open with acl_use_db.
-- Written for the duckdb dialect; see schema/acl_schema.sql for what another engine may need changing.
-- Every issuer becomes the short form: an issuer named by its URL, and its implicit client (same name)
-- carrying its audiences, role claim, claim map and client id. Its mappings move to the implicit
-- client's scope: that client was the issuer's only one, so they mean what they meant - including a
-- mapping to a role with an administration scope, which spec 095 allows from a client only.
-- An issuer without audiences (v16: no audience check) becomes a client that accepts NO token until
-- ALTER ISSUER '<url>' SET AUDIENCES (...) names them - fail closed, not "any".
-- DROPPED, deliberately: keys_json, algs, jwks_uri and client_secret - no key and no credential is
-- kept in the policy. An issuer that relied on pasted keys, a KEYS FROM location or a client secret
-- needs an oidc_issuer / oidc_client secret in the secrets service after this step (FROM SECRET), or
-- reads its keys by OIDC discovery. An audience '*' no longer means "any": name the audiences.
ALTER TABLE acl."issuers" RENAME TO "issuers_old";
CREATE TABLE acl."issuers"("name" VARCHAR PRIMARY KEY, "url" VARCHAR, "secret_service" VARCHAR, "secret" VARCHAR);
INSERT INTO acl."issuers" SELECT "issuer", "issuer", NULL, NULL FROM acl."issuers_old";
CREATE TABLE IF NOT EXISTS acl."clients"("name" VARCHAR PRIMARY KEY, "issuer" VARCHAR, "audiences" VARCHAR, "azp" VARCHAR, "requires" VARCHAR, "roles_from" VARCHAR, "roles_constant" VARCHAR, "unmapped" VARCHAR, "attributes" VARCHAR, "subject" VARCHAR, "token_type" VARCHAR, "client_id" VARCHAR, "flows" VARCHAR, "secret_service" VARCHAR, "secret" VARCHAR, "implicit" BOOLEAN);
INSERT INTO acl."clients" SELECT "issuer", "issuer", NULLIF("audiences", ''), NULL, NULL, COALESCE(NULLIF("role_claim", ''), 'roles'), NULL, 'as_role', NULLIF("claim_map", ''), NULL, NULL, NULLIF("client_id", ''), CASE WHEN COALESCE("client_id", '') = '' THEN NULL WHEN COALESCE("client_secret", '') <> '' THEN 'password' ELSE 'password,authcode,device' END, NULL, NULL, true FROM acl."issuers_old";
ALTER TABLE acl."role_mappings" RENAME TO "role_mappings_old";
CREATE TABLE acl."role_mappings"("scope_kind" VARCHAR, "scope_name" VARCHAR, "source" VARCHAR, "external_value" VARCHAR, "role" VARCHAR, PRIMARY KEY ("scope_kind", "scope_name", "source", "external_value", "role"));
INSERT INTO acl."role_mappings" SELECT 'client', "issuer", "source", "external_value", "role" FROM acl."role_mappings_old";
DROP TABLE acl."role_mappings_old";
DROP TABLE acl."issuers_old";
DELETE FROM acl."meta" WHERE "key" = 'min_reader_version';
INSERT INTO acl."meta" VALUES ('min_reader_version', '17');
UPDATE acl."meta" SET "value" = '17' WHERE "key" = 'schema_version';
