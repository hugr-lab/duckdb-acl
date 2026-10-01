-- End-to-end demo of the acl extension acting as the enforcement layer behind a gateway.
-- Run via test/harness/run.sh (which LOADs the built extension first and checks what happens).
-- Four statements below are MEANT to be refused; the runner counts on exactly those four.

-- 1) a "physical" database holding the real data (a principal never names it directly)
ATTACH ':memory:' AS phys;
CREATE TABLE phys.main.orders(id INT, tenant VARCHAR, amount INT, ssn VARCHAR);
INSERT INTO phys.main.orders VALUES
  (1, 'acme', 100, 'a-secret'),
  (2, 'globex', 200, 'g-secret'),
  (3, 'acme', 300, 'a-secret-2');

-- 2) the policy catalog: an ATTACHed database the extension manages (here in memory; in production
--    a durable one). acl_allow_anonymous_admin is the bootstrap hatch a gateway opens once to write the
--    first policy - it is closed again at the end of this demo.
ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true);
SET GLOBAL acl_allow_anonymous_admin = true;

-- 3) the policy, in management SQL (every statement compiles to one acl_* function)
ACL ADMIN CREATE VIRTUAL CATALOG sales COMMENT 'what analysts see';
--    'orders' -> a read-only projection: only id+amount, ssn masked to NULL, RLS on the tenant claim
ACL ADMIN CREATE VIRTUAL TABLE sales.orders AS phys.main.orders
    COLUMNS (id, amount, ssn = NULL::VARCHAR) RLS (tenant = acl_claim('tenant'));
--    'raw_orders' -> a writable alias of the physical table (no projection, no predicate)
ACL ADMIN CREATE VIRTUAL TABLE sales.raw_orders AS phys.main.orders;
--    a virtual scalar that tags a value with the caller's tenant
ACL ADMIN CREATE VIRTUAL SCALAR sales.tenant_tag(v VARCHAR) RETURNS VARCHAR AS acl_arg(1) || '@' || acl_claim('tenant');
--    the role, with a default claim for the bare ROLE form, and its grant on the catalog
ACL ADMIN CREATE ROLE analyst CLAIMS (tenant = 'globex');
ACL ADMIN GRANT CATALOG sales TO ROLE analyst WITH (select, insert) MAIN;
--    an issuer whose tokens verify offline: its keys are found by its OIDC discovery (here a fixture
--    under test/idp/, which this node is told it may read; in production the IdP's https URL). The
--    token's `aud` must be one of the AUDIENCES, its `roles` claim names the role, and its `tid` claim
--    becomes acl_claim('tenant')
SET GLOBAL acl_jwks_locations = 'test/idp/';
ACL ADMIN CREATE ISSUER 'test/idp/demo' AUDIENCES ('api://acl-demo') ROLE CLAIM 'roles' CLAIM MAP (tid => tenant);

-- 4) from here the gateway prefixes every statement with the principal
.print '--- ROLE analyst (default claim tenant=globex): RLS keeps only globex rows, ssn masked ---'
ACL ROLE "analyst" SELECT id, amount, ssn FROM orders ORDER BY id;

.print '--- TOKEN (a JWT with tid=acme, roles=[analyst]): a different claim, the same policy ---'
ACL TOKEN 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9kZW1vIiwiYXVkIjoiYXBpOi8vYWNsLWRlbW8iLCJzdWIiOiJ1c2VyLTEiLCJyb2xlcyI6WyJhbmFseXN0Il0sInRpZCI6ImFjbWUiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMH0.fR5MGrMp9sa8e-LYuLfXCLLyC0nS4zp_JqitcnsAJn8twM2m5LMfgvERbUi85tbvWGxOwFS1qdxcTK1pVE3Ix1-Kx-H6iS2AwB2bhPgr8mF7J14IXulKeCsDFPvEWtJKRmbBMj-h2D-q5wugm6POrWxN-AG6GiTkAZ-iR2x8hc60fdxtQO9by-NsU9VMaOiddk7En8Qud1B9gEXxko0wWLJEpBZjq7DOZMFd5cL-wPU9Osh3PiYE8zxKL2J2uoadkqmkZYrMeTPN33IKoDA-p96JEwhXw_0F_AM2P9DtBNjrcA02feZvRV4E7xLnwyun3ySnex-h2Z36eU_9cm-PEA' SELECT id, amount, ssn FROM orders ORDER BY id;

.print '--- (refused 1/4) a physical name is not in the virtual catalog ---'
ACL ROLE "analyst" SELECT * FROM phys.main.orders;

.print '--- (refused 2/4) a data-reading function is denied ---'
ACL ROLE "analyst" SELECT * FROM read_csv('/etc/passwd');

.print '--- a virtual scalar expands with the baked claim ---'
ACL ROLE "analyst" SELECT tenant_tag('user-1') AS tag;

.print '--- DML works on a writable alias ---'
ACL ROLE "analyst" INSERT INTO raw_orders VALUES (9, 'globex', 999, 'x');
.print '(inserted; the physical row, read by the administrator:)'
ACL ADMIN SELECT id, tenant, amount FROM phys.main.orders WHERE id = 9;

.print '--- (refused 3/4) writing through a read-only (masked/RLS) relation ---'
ACL ROLE "analyst" INSERT INTO orders VALUES (10, 'globex', 1);

.print '--- (refused 4/4) with the bootstrap hatch closed, the anonymous ACL ADMIN form is gone too ---'
SET GLOBAL acl_allow_anonymous_admin = false;
ACL ADMIN SELECT count(*) FROM phys.main.orders;

.print '--- the audit counted every refusal above under its code (spec 069) ---'
-- the counters are the audit pipeline's, derived on its worker: wait for the last refusal to reach it
SELECT acl_audit_flush() AS flushed;
SELECT name, attributes, value FROM acl_metrics() WHERE name = 'acl.denials' ORDER BY attributes;
