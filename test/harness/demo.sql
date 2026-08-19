-- End-to-end demo of the acl extension acting as the enforcement layer behind a gateway.
-- Run via test/harness/run.sh (which LOADs the built extension first).

-- 1) a "physical" database holding the real data (a sandboxed role never names it directly)
ATTACH ':memory:' AS phys;
CREATE TABLE phys.main.orders(id INT, tenant VARCHAR, amount INT, ssn VARCHAR);
INSERT INTO phys.main.orders VALUES
  (1, 'acme', 100, 'a-secret'),
  (2, 'globex', 200, 'g-secret'),
  (3, 'acme', 300, 'a-secret-2');

-- 2) admin registers policy (in production this is the read-only ACL resolver, not SQL calls)
--    'orders' -> read-only SUBQUERY: only id+amount, ssn masked to NULL, RLS on the tenant claim
SELECT acl_grant_table('analyst', 'orders', 'phys.main.orders',
                       'id,amount,ssn=NULL', 'tenant = acl_claim(''tenant'')', 'select');
--    'raw_orders' -> writable RENAME of the physical table (no projection/RLS)
SELECT acl_grant_table('analyst', 'raw_orders', 'phys.main.orders', '', '', 'select,insert');
--    a virtual scalar that tags a value with the caller's tenant
SELECT acl_grant_scalar('analyst', 'tenant_tag', 'acl_arg(1) || ''@'' || acl_claim(''tenant'')');

-- principals
SELECT acl_define_token('tok-acme', 'analyst', 'tenant=acme');
SELECT acl_define_role('analyst', 'tenant=globex');   -- default claims for the bare ROLE form

-- 3) turn on the override; from here the gateway prefixes every query
SET allow_parser_override_extension = 'fallback';

.print '--- ROLE analyst (tenant=globex): RLS keeps only globex rows, ssn masked ---'
ACL ROLE "analyst" SELECT id, amount, ssn FROM orders ORDER BY id;

.print '--- TOKEN tok-acme (tenant=acme): different claim, same policy ---'
ACL TOKEN 'tok-acme' SELECT id, amount, ssn FROM orders ORDER BY id;

.print '--- a forbidden physical name is denied ---'
ACL ROLE "analyst" SELECT * FROM phys.main.orders;

.print '--- a data-reading function is denied ---'
ACL ROLE "analyst" SELECT * FROM read_csv('/etc/passwd');

.print '--- a virtual scalar function expands with the baked claim ---'
ACL TOKEN 'tok-acme' SELECT tenant_tag('user-1') AS tag;

.print '--- DML works on a writable RENAME relation ---'
ACL TOKEN 'tok-acme' INSERT INTO raw_orders VALUES (9, 'acme', 999, 'x');
.print '(inserted; physical row now present:)'
ACL ADMIN SELECT id, tenant, amount FROM phys.main.orders WHERE id = 9;

.print '--- writing through a read-only (masked/RLS) relation is refused ---'
ACL TOKEN 'tok-acme' INSERT INTO orders VALUES (10, 'acme', 1);
