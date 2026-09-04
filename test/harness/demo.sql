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
--    an issuer whose tokens verify offline (HS256 here; RS256/ES256 or KEYS FROM a JWKS in production):
--    the token's `roles` claim names the role, its `tid` claim becomes acl_claim('tenant')
ACL ADMIN CREATE ISSUER 'https://issuer.demo' KEYS '{"keys":[{"kty":"oct","k":"YWNsLXRlc3QtaHMyNTYtc2VjcmV0"}]}'
    ALGS (HS256) ROLE CLAIM 'roles' CLAIM MAP (tid => tenant);

-- 4) from here the gateway prefixes every statement with the principal
.print '--- ROLE analyst (default claim tenant=globex): RLS keeps only globex rows, ssn masked ---'
ACL ROLE "analyst" SELECT id, amount, ssn FROM orders ORDER BY id;

.print '--- TOKEN (a JWT with tid=acme, roles=[analyst]): a different claim, the same policy ---'
ACL TOKEN 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5kZW1vIiwic3ViIjoidXNlci0xIiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9.F14wQi-RR1pxrcuHYhIeHcqM9GeIM1d9qnP9m6EDvy8' SELECT id, amount, ssn FROM orders ORDER BY id;

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
SELECT name, attributes, value FROM acl_metrics() WHERE name = 'acl.denials' ORDER BY attributes;
